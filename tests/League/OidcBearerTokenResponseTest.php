<?php

declare(strict_types=1);

namespace DarkSide\OpenIdConnectServer\Tests\League;

use DateTimeImmutable;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\ScopeEntityInterface;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamInterface;
use DarkSide\OpenIdConnectServer\Identity\ArrayIdentity;
use DarkSide\OpenIdConnectServer\Identity\IdentityResolverInterface;
use DarkSide\OpenIdConnectServer\League\OidcBearerTokenResponse;
use DarkSide\OpenIdConnectServer\Tests\Support\RsaKeyPair;
use DarkSide\OpenIdConnectServer\Token\IdTokenIssuer;
use DarkSide\OpenIdConnectServer\Transaction\OidcRequestContext;
use DarkSide\OpenIdConnectServer\Transaction\RequestScopedOidcContextProvider;

final class OidcBearerTokenResponseTest extends TestCase
{
    public function testItAddsAnIdTokenWithTheNonceBoundToTheRedeemedCode(): void
    {
        $key = RsaKeyPair::generate();
        $context = new OidcRequestContext();
        $context->setRedeemedNonce('nonce-from-authorized-transaction');

        $resolver = new class () implements IdentityResolverInterface {
            public function resolve(string $userIdentifier, string $clientId, array $grantedScopes): \DarkSide\OpenIdConnectServer\Identity\IdentityInterface
            {
                TestCase::assertSame('user-42', $userIdentifier);
                TestCase::assertSame('client-7', $clientId);
                TestCase::assertSame(['openid', 'profile'], $grantedScopes);

                return new ArrayIdentity('stable-subject-42', ['name' => 'Test User']);
            }
        };

        $responseType = new OidcBearerTokenResponse(
            new IdTokenIssuer('https://issuer.example.test', $key),
            $resolver,
            new RequestScopedOidcContextProvider($context),
        );

        $openidScope = $this->createMock(ScopeEntityInterface::class);
        $openidScope->method('getIdentifier')->willReturn('openid');
        $profileScope = $this->createMock(ScopeEntityInterface::class);
        $profileScope->method('getIdentifier')->willReturn('profile');
        $client = $this->createMock(ClientEntityInterface::class);
        $client->method('getIdentifier')->willReturn('client-7');
        $accessToken = $this->createMock(AccessTokenEntityInterface::class);
        $accessToken->method('getScopes')->willReturn([$openidScope, $profileScope]);
        $accessToken->method('getUserIdentifier')->willReturn('user-42');
        $accessToken->method('getClient')->willReturn($client);
        $accessToken->method('getExpiryDateTime')->willReturn(new DateTimeImmutable('+5 minutes'));
        $accessToken->method('toString')->willReturn('opaque-access-token');
        $responseType->setAccessToken($accessToken);

        $body = '';
        $response = $this->createMock(ResponseInterface::class);
        $response->expects(self::once())->method('withStatus')->with(200)->willReturnSelf();
        $response->expects(self::exactly(3))->method('withHeader')->willReturnSelf();

        $stream = $this->createMock(StreamInterface::class);
        $stream->expects(self::once())->method('write')->willReturnCallback(
            static function (string $contents) use (&$body): int {
                $body = $contents;

                return strlen($contents);
            },
        );
        $response->method('getBody')->willReturn($stream);

        $result = $responseType->generateHttpResponse($response);

        self::assertSame($response, $result);
        $payload = json_decode($body, true, 512, JSON_THROW_ON_ERROR);
        self::assertArrayHasKey('access_token', $payload);
        self::assertArrayHasKey('id_token', $payload);
        self::assertArrayNotHasKey('refresh_token', $payload);
        self::assertNull($context->consumeRedeemedNonce(), 'The nonce must be consumed exactly once.');

        $verification = \Lcobucci\JWT\Configuration::forAsymmetricSigner(
            new \Lcobucci\JWT\Signer\Rsa\Sha256(),
            \Lcobucci\JWT\Signer\Key\InMemory::plainText($key->privateKeyPem),
            \Lcobucci\JWT\Signer\Key\InMemory::plainText($key->publicKeyPem),
        );
        $idToken = $verification->parser()->parse($payload['id_token']);

        self::assertSame('stable-subject-42', $idToken->claims()->get('sub'));
        self::assertSame('nonce-from-authorized-transaction', $idToken->claims()->get('nonce'));
        $audience = $idToken->claims()->get('aud');
        self::assertTrue($audience === 'client-7' || (is_array($audience) && in_array('client-7', $audience, true)));
        self::assertSame('Test User', $idToken->claims()->get('name'));
        self::assertTrue($verification->validator()->validate(
            $idToken,
            new \Lcobucci\JWT\Validation\Constraint\SignedWith(
                new \Lcobucci\JWT\Signer\Rsa\Sha256(),
                \Lcobucci\JWT\Signer\Key\InMemory::plainText($key->publicKeyPem),
            ),
        ));
    }

    public function testItFailsClosedWhenRedeemedCodeHasNoNonce(): void
    {
        $key = RsaKeyPair::generate();
        $context = new OidcRequestContext();
        $responseType = new OidcBearerTokenResponse(
            new IdTokenIssuer('https://issuer.example.test', $key),
            new class () implements IdentityResolverInterface {
                public function resolve(string $userIdentifier, string $clientId, array $grantedScopes): \DarkSide\OpenIdConnectServer\Identity\IdentityInterface
                {
                    return new ArrayIdentity('stable-subject');
                }
            },
            new RequestScopedOidcContextProvider($context),
        );

        $scope = $this->createMock(ScopeEntityInterface::class);
        $scope->method('getIdentifier')->willReturn('openid');
        $client = $this->createMock(ClientEntityInterface::class);
        $client->method('getIdentifier')->willReturn('client-7');
        $accessToken = $this->createMock(AccessTokenEntityInterface::class);
        $accessToken->method('getScopes')->willReturn([$scope]);
        $accessToken->method('getUserIdentifier')->willReturn('user-42');
        $accessToken->method('getClient')->willReturn($client);
        $accessToken->method('getExpiryDateTime')->willReturn(new DateTimeImmutable('+5 minutes'));
        $accessToken->method('toString')->willReturn('opaque-access-token');

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('did not provide its bound OIDC nonce');
        $responseType->setAccessToken($accessToken);
        $responseType->generateHttpResponse($this->createMock(ResponseInterface::class));
    }

    public function testItDoesNotIssueAnIdTokenForNonOpenIdAccessTokens(): void
    {
        $key = RsaKeyPair::generate();
        $context = new OidcRequestContext();
        $responseType = new OidcBearerTokenResponse(
            new IdTokenIssuer('https://issuer.example.test', $key),
            new class () implements IdentityResolverInterface {
                public function resolve(string $userIdentifier, string $clientId, array $grantedScopes): \DarkSide\OpenIdConnectServer\Identity\IdentityInterface
                {
                    TestCase::fail('Identity resolution must not run for a non-OIDC access token.');
                }
            },
            new RequestScopedOidcContextProvider($context),
        );

        $scope = $this->createMock(ScopeEntityInterface::class);
        $scope->method('getIdentifier')->willReturn('profile');
        $accessToken = $this->createMock(AccessTokenEntityInterface::class);
        $accessToken->method('getScopes')->willReturn([$scope]);
        $accessToken->method('getExpiryDateTime')->willReturn(new DateTimeImmutable('+5 minutes'));
        $accessToken->method('toString')->willReturn('opaque-access-token');
        $responseType->setAccessToken($accessToken);

        $body = '';
        $response = $this->createMock(ResponseInterface::class);
        $response->method('withStatus')->willReturnSelf();
        $response->method('withHeader')->willReturnSelf();
        $stream = $this->createMock(StreamInterface::class);
        $stream->method('write')->willReturnCallback(static function (string $contents) use (&$body): int {
            $body = $contents;

            return strlen($contents);
        });
        $response->method('getBody')->willReturn($stream);

        $responseType->generateHttpResponse($response);
        $payload = json_decode($body, true, 512, JSON_THROW_ON_ERROR);
        self::assertArrayNotHasKey('id_token', $payload);
        self::assertNull($context->consumeRedeemedNonce());
    }
}
