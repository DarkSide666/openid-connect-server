<?php

declare(strict_types=1);

namespace DarkSide\OpenIdConnectServer\Tests\League;

use DateInterval;
use DateTimeImmutable;
use Defuse\Crypto\Key;
use League\OAuth2\Server\AuthorizationServer;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\AuthCodeEntityInterface;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\Entities\UserEntityInterface;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\StreamInterface;
use DarkSide\OpenIdConnectServer\Identity\ArrayIdentity;
use DarkSide\OpenIdConnectServer\Identity\IdentityResolverInterface;
use DarkSide\OpenIdConnectServer\Key\SigningKey;
use DarkSide\OpenIdConnectServer\League\OidcAuthCodeGrant;
use DarkSide\OpenIdConnectServer\League\OidcAuthCodeRepository;
use DarkSide\OpenIdConnectServer\League\OidcBearerTokenResponse;
use DarkSide\OpenIdConnectServer\Tests\Support\InMemoryAuthorizationCodeMetadataStore;
use DarkSide\OpenIdConnectServer\Tests\Support\InMemoryLeagueAccessTokenRepository;
use DarkSide\OpenIdConnectServer\Tests\Support\InMemoryLeagueAuthCodeRepository;
use DarkSide\OpenIdConnectServer\Tests\Support\InMemoryLeagueClientRepository;
use DarkSide\OpenIdConnectServer\Tests\Support\InMemoryLeagueScopeRepository;
use DarkSide\OpenIdConnectServer\Tests\Support\NullLeagueRefreshTokenRepository;
use DarkSide\OpenIdConnectServer\Tests\Support\MutableTestOidcContextProvider;
use DarkSide\OpenIdConnectServer\Tests\Support\RsaKeyPair;
use DarkSide\OpenIdConnectServer\Token\IdTokenIssuer;
use DarkSide\OpenIdConnectServer\Transaction\OidcRequestContext;

use function base64_encode;
use function hash;
use function parse_str;
use function parse_url;
use function rtrim;
use function sys_get_temp_dir;
use function tempnam;
use function unlink;

/**
 * Exercises the real League AuthorizationServer, AuthCodeGrant and BearerTokenResponse.
 * Repository/entity mocks represent application-owned persistence boundaries only.
 */
final class LeagueAuthorizationCodeFlowTest extends TestCase
{
    public const CLIENT_ID = 'oidc-test-client';
    public const REDIRECT_URI = 'https://client.example.test/callback';
    public const USER_ID = 'user-314';
    public const NONCE = 'nonce-bound-to-this-authorization-request';
    public const VERIFIER = 'a-very-long-pkce-verifier-value-with-at-least-43-characters-123456789';
    private const CLIENT_SECRET = 'correct-client-secret';

    private AuthorizationServer $server;
    private MutableTestOidcContextProvider $contextProvider;
    private SigningKey $signingKey;
    private string $privateKeyPath;
    private string $authorizationCode;
    private InMemoryLeagueAuthCodeRepository $innerAuthCodeRepository;

    protected function setUp(): void
    {
        parent::setUp();

        $this->signingKey = RsaKeyPair::generate('flow-test-key');
        $privateKeyPath = tempnam(sys_get_temp_dir(), 'oidc-league-key-');
        if ($privateKeyPath === false) {
            self::fail('Unable to create a temporary League signing key file.');
        }
        $this->privateKeyPath = $privateKeyPath;
        if (file_put_contents($this->privateKeyPath, $this->signingKey->privateKeyPem) === false) {
            self::fail('Unable to write the temporary League signing key file.');
        }

        $this->contextProvider = new MutableTestOidcContextProvider(new OidcRequestContext());
        $metadataStore = new InMemoryAuthorizationCodeMetadataStore();

        $client = $this->createMock(ClientEntityInterface::class);
        $client->method('getIdentifier')->willReturn(self::CLIENT_ID);
        $client->method('getName')->willReturn('OIDC integration test client');
        $client->method('getRedirectUri')->willReturn(self::REDIRECT_URI);
        $client->method('isConfidential')->willReturn(true);

        $otherClient = $this->createMock(ClientEntityInterface::class);
        $otherClient->method('getIdentifier')->willReturn('other-client');
        $otherClient->method('getName')->willReturn('Other test client');
        $otherClient->method('getRedirectUri')->willReturn('https://other.example.test/callback');
        $otherClient->method('isConfidential')->willReturn(true);

        $clientRepository = new InMemoryLeagueClientRepository(
            [self::CLIENT_ID => $client, 'other-client' => $otherClient],
            [self::CLIENT_ID => self::CLIENT_SECRET, 'other-client' => 'other-client-secret'],
        );

        $openidScope = $this->createMock(ScopeEntityInterface::class);
        $openidScope->method('getIdentifier')->willReturn('openid');
        // League JSON-encodes scope entities into the authorization-code
        // payload. ScopeTrait normally serializes each entity to its string
        // identifier; PHPUnit mocks need that behavior configured explicitly.
        $openidScope->method('jsonSerialize')->willReturn('openid');

        $profileScope = $this->createMock(ScopeEntityInterface::class);
        $profileScope->method('getIdentifier')->willReturn('profile');
        $profileScope->method('jsonSerialize')->willReturn('profile');
        $scopeRepository = new InMemoryLeagueScopeRepository([
            'openid' => $openidScope,
            'profile' => $profileScope,
        ]);

        $authCodeEntity = $this->createMock(AuthCodeEntityInterface::class);
        $authCodeScopes = [];
        $authCodeEntity->method('getIdentifier')->willReturn('league-auth-code-id-0001');
        $authCodeEntity->method('getClient')->willReturn($client);
        $authCodeEntity->method('getRedirectUri')->willReturn(self::REDIRECT_URI);
        $authCodeEntity->method('getUserIdentifier')->willReturn(self::USER_ID);
        // League mutates the entity returned by getNewAuthCode() before it
        // serializes the authorization-code payload. Keep the mock stateful:
        // otherwise its getters can return stale fixture values after setters
        // have been called, producing malformed scope data in the code payload.
        $authCodeEntity->method('getScopes')->willReturnCallback(
            static function () use (&$authCodeScopes): array {
                return $authCodeScopes;
            },
        );
        $authCodeEntity->method('addScope')->willReturnCallback(
            static function (ScopeEntityInterface $scope) use (&$authCodeScopes): void {
                $authCodeScopes[] = $scope;
            },
        );
        $authCodeEntity->method('getExpiryDateTime')->willReturn(new DateTimeImmutable('+5 minutes'));

        $this->innerAuthCodeRepository = new InMemoryLeagueAuthCodeRepository($authCodeEntity);

        $authCodeRepository = new OidcAuthCodeRepository(
            $this->innerAuthCodeRepository,
            $metadataStore,
            $this->contextProvider,
        );

        $accessTokenEntity = $this->createMock(AccessTokenEntityInterface::class);
        $accessTokenEntity->method('getExpiryDateTime')->willReturn(new DateTimeImmutable('+5 minutes'));
        $accessTokenEntity->method('getScopes')->willReturn([$openidScope, $profileScope]);
        $accessTokenEntity->method('getUserIdentifier')->willReturn(self::USER_ID);
        $accessTokenEntity->method('getClient')->willReturn($client);
        $accessTokenEntity->method('toString')->willReturn('test-access-token-value');

        $accessTokenRepository = new InMemoryLeagueAccessTokenRepository($accessTokenEntity);
        $refreshTokenRepository = new NullLeagueRefreshTokenRepository();

        $identityResolver = new class () implements IdentityResolverInterface {
            public function resolve(string $userIdentifier, string $clientId, array $grantedScopes): \DarkSide\OpenIdConnectServer\Identity\IdentityInterface
            {
                TestCase::assertSame(LeagueAuthorizationCodeFlowTest::USER_ID, $userIdentifier);
                TestCase::assertSame(LeagueAuthorizationCodeFlowTest::CLIENT_ID, $clientId);
                TestCase::assertSame(['openid', 'profile'], $grantedScopes);

                return new ArrayIdentity('immutable-subject-314', ['name' => 'Integration Test User'], new DateTimeImmutable('-60 seconds'));
            }
        };

        $responseType = new OidcBearerTokenResponse(
            new IdTokenIssuer('https://issuer.example.test', $this->signingKey),
            $identityResolver,
            $this->contextProvider,
        );

        $grant = new OidcAuthCodeGrant(
            $authCodeRepository,
            $refreshTokenRepository,
            new DateInterval('PT5M'),
            $this->contextProvider,
        );

        $this->server = new AuthorizationServer(
            $clientRepository,
            $accessTokenRepository,
            $scopeRepository,
            $this->privateKeyPath,
            Key::createNewRandomKey()->saveToAsciiSafeString(),
            $responseType,
        );
        $this->server->enableGrantType($grant, new DateInterval('PT5M'));

        $this->authorizationCode = $this->authorizeAndCaptureCode();
    }

    protected function tearDown(): void
    {
        if (isset($this->privateKeyPath) && is_file($this->privateKeyPath)) {
            unlink($this->privateKeyPath);
        }

        parent::tearDown();
    }

    public function testCompleteAuthorizationCodePkceFlowIssuesVerifiableIdToken(): void
    {
        $this->contextProvider->beginRequest();
        $tokenResponse = $this->exchangeAuthorizationCode($this->authorizationCode, self::VERIFIER);

        self::assertSame(200, $tokenResponse->getStatusCode());
        $payload = json_decode((string) $tokenResponse->getBody(), true, 512, JSON_THROW_ON_ERROR);

        self::assertArrayHasKey('access_token', $payload);
        self::assertSame('test-access-token-value', $payload['access_token']);
        self::assertArrayHasKey('id_token', $payload);
        self::assertArrayNotHasKey('refresh_token', $payload);

        $verification = \Lcobucci\JWT\Configuration::forAsymmetricSigner(
            new \Lcobucci\JWT\Signer\Rsa\Sha256(),
            \Lcobucci\JWT\Signer\Key\InMemory::plainText($this->signingKey->privateKeyPem),
            \Lcobucci\JWT\Signer\Key\InMemory::plainText($this->signingKey->publicKeyPem),
        );
        $idToken = $verification->parser()->parse($payload['id_token']);

        self::assertSame('https://issuer.example.test', $idToken->claims()->get('iss'));
        self::assertSame('immutable-subject-314', $idToken->claims()->get('sub'));
        self::assertSame(self::NONCE, $idToken->claims()->get('nonce'));
        self::assertSame('Integration Test User', $idToken->claims()->get('name'));
        self::assertIsInt($idToken->claims()->get('auth_time'));
        self::assertLessThanOrEqual(time(), $idToken->claims()->get('auth_time'));
        $audience = $idToken->claims()->get('aud');
        self::assertTrue(
            $audience === self::CLIENT_ID
            || (is_array($audience) && in_array(self::CLIENT_ID, $audience, true)),
        );
        self::assertTrue($verification->validator()->validate(
            $idToken,
            new \Lcobucci\JWT\Validation\Constraint\SignedWith(
                new \Lcobucci\JWT\Signer\Rsa\Sha256(),
                \Lcobucci\JWT\Signer\Key\InMemory::plainText($this->signingKey->publicKeyPem),
            ),
        ));
        self::assertTrue(
            $this->innerAuthCodeRepository->isAuthCodeRevoked('league-auth-code-id-0001'),
            'League must revoke the authorization code after redemption.',
        );
    }

    public function testAuthorizationCodeCannotBeRedeemedTwice(): void
    {
        $this->contextProvider->beginRequest();
        $this->exchangeAuthorizationCode($this->authorizationCode, self::VERIFIER);

        $this->contextProvider->beginRequest();
        $this->expectException(\League\OAuth2\Server\Exception\OAuthServerException::class);
        $this->exchangeAuthorizationCode($this->authorizationCode, self::VERIFIER);
    }

    public function testIncorrectPkceVerifierIsRejected(): void
    {
        $this->contextProvider->beginRequest();
        $this->expectException(\League\OAuth2\Server\Exception\OAuthServerException::class);
        $this->exchangeAuthorizationCode($this->authorizationCode, 'incorrect-verifier-value-that-is-long-enough-to-pass-the-format-check');
    }

    public function testRedirectUriMismatchIsRejected(): void
    {
        $this->contextProvider->beginRequest();
        $this->expectException(\League\OAuth2\Server\Exception\OAuthServerException::class);
        $this->exchangeAuthorizationCode(
            $this->authorizationCode,
            self::VERIFIER,
            'https://attacker.example.test/callback',
        );
    }

    public function testAuthorizationCodeCannotBeRedeemedByAnotherClient(): void
    {
        $this->contextProvider->beginRequest();
        $this->expectException(\League\OAuth2\Server\Exception\OAuthServerException::class);
        $this->exchangeAuthorizationCode(
            $this->authorizationCode,
            self::VERIFIER,
            self::REDIRECT_URI,
            'other-client',
            'other-client-secret',
        );
    }

    public function testIncorrectClientSecretIsRejected(): void
    {
        $this->contextProvider->beginRequest();
        $this->expectException(\League\OAuth2\Server\Exception\OAuthServerException::class);
        $this->exchangeAuthorizationCode(
            $this->authorizationCode,
            self::VERIFIER,
            self::REDIRECT_URI,
            self::CLIENT_ID,
            'incorrect-client-secret',
        );
    }

    private function authorizeAndCaptureCode(): string
    {
        $request = $this->serverRequest([
            'response_type' => 'code',
            'client_id' => self::CLIENT_ID,
            'redirect_uri' => self::REDIRECT_URI,
            'scope' => 'openid profile',
            'state' => 'state-abc',
            'nonce' => self::NONCE,
            'max_age' => '300',
            'code_challenge' => $this->codeChallenge(self::VERIFIER),
            'code_challenge_method' => 'S256',
        ]);

        $authorizationRequest = $this->server->validateAuthorizationRequest($request);
        $user = $this->createMock(UserEntityInterface::class);
        $user->method('getIdentifier')->willReturn(self::USER_ID);
        $authorizationRequest->setUser($user);
        $authorizationRequest->setAuthorizationApproved(true);

        $location = null;
        $response = $this->createMock(ResponseInterface::class);
        $response->method('withStatus')->willReturnSelf();
        $response->method('withHeader')->willReturnCallback(
            function (string $name, $value) use (&$location, $response): ResponseInterface {
                if (strtolower($name) === 'location') {
                    $location = is_array($value) ? $value[0] : $value;
                }

                return $response;
            },
        );

        $this->server->completeAuthorizationRequest($authorizationRequest, $response);
        self::assertIsString($location);

        $query = parse_url($location, PHP_URL_QUERY);
        self::assertIsString($query);
        parse_str($query, $parameters);
        self::assertArrayHasKey('code', $parameters);
        self::assertSame('state-abc', $parameters['state']);

        return $parameters['code'];
    }

    private function exchangeAuthorizationCode(
        string $code,
        string $verifier,
        string $redirectUri = self::REDIRECT_URI,
        string $clientId = self::CLIENT_ID,
        string $clientSecret = self::CLIENT_SECRET,
    ): ResponseInterface {
        $request = $this->serverRequest([], [
            'grant_type' => 'authorization_code',
            'client_id' => $clientId,
            'client_secret' => $clientSecret,
            'code' => $code,
            'redirect_uri' => $redirectUri,
            'code_verifier' => $verifier,
        ]);

        $body = '';
        $response = $this->createMock(ResponseInterface::class);
        $response->method('withStatus')->willReturnSelf();
        $response->method('withHeader')->willReturnSelf();
        $response->method('getStatusCode')->willReturn(200);
        $stream = $this->createMock(StreamInterface::class);
        $stream->method('write')->willReturnCallback(static function (string $contents) use (&$body): int {
            $body = $contents;

            return strlen($contents);
        });
        $stream->method('__toString')->willReturnCallback(static function () use (&$body): string {
            return $body;
        });
        $response->method('getBody')->willReturn($stream);

        $result = $this->server->respondToAccessTokenRequest($request, $response);
        self::assertSame(200, $result->getStatusCode());

        return $result;
    }

    /** @param array<string, mixed> $query @param array<string, mixed> $parsedBody */
    private function serverRequest(array $query, array $parsedBody = []): ServerRequestInterface
    {
        $request = $this->createMock(ServerRequestInterface::class);
        $request->method('getQueryParams')->willReturn($query);
        $request->method('getParsedBody')->willReturn($parsedBody);
        $request->method('getServerParams')->willReturn([]);
        $request->method('getHeaderLine')->willReturn('');
        $request->method('hasHeader')->willReturn(false);
        $request->method('getHeader')->willReturn([]);

        return $request;
    }

    private function codeChallenge(string $verifier): string
    {
        return rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');
    }
}
