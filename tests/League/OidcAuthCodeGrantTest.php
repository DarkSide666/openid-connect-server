<?php

declare(strict_types=1);

namespace DarkSide\OpenIdConnectServer\Tests\League;

use DateInterval;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Repositories\AuthCodeRepositoryInterface;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use DarkSide\OpenIdConnectServer\League\OidcAuthCodeGrant;
use DarkSide\OpenIdConnectServer\League\OidcAuthorizationRequest;
use DarkSide\OpenIdConnectServer\Transaction\OidcRequestContext;
use DarkSide\OpenIdConnectServer\Transaction\RequestScopedOidcContextProvider;

final class OidcAuthCodeGrantTest extends TestCase
{
    public function testItRequiresOpenIdNonceAndS256Pkce(): void
    {
        $grant = $this->createGrant();
        $authorizationRequest = $grant->validateAuthorizationRequest($this->authorizationRequest([
            'response_type' => 'code',
            'client_id' => 'client-1',
            'redirect_uri' => 'https://client.example/callback',
            'scope' => 'openid',
            'code_challenge' => str_repeat('A', 43),
            'code_challenge_method' => 'S256',
            'nonce' => 'nonce-123',
        ]));

        self::assertInstanceOf(OidcAuthorizationRequest::class, $authorizationRequest);
        self::assertSame('nonce-123', $authorizationRequest->nonce());
        self::assertSame('S256', $authorizationRequest->getCodeChallengeMethod());
    }

    public function testItRejectsAuthorizationRequestWithoutNonce(): void
    {
        $grant = $this->createGrant();
        $this->expectException(OAuthServerException::class);

        $grant->validateAuthorizationRequest($this->authorizationRequest([
            'response_type' => 'code',
            'client_id' => 'client-1',
            'redirect_uri' => 'https://client.example/callback',
            'scope' => 'openid',
            'code_challenge' => str_repeat('A', 43),
            'code_challenge_method' => 'S256',
        ]));
    }

    public function testItRejectsPlainPkce(): void
    {
        $grant = $this->createGrant();
        $this->expectException(OAuthServerException::class);

        $grant->validateAuthorizationRequest($this->authorizationRequest([
            'response_type' => 'code',
            'client_id' => 'client-1',
            'redirect_uri' => 'https://client.example/callback',
            'scope' => 'openid',
            'code_challenge' => str_repeat('A', 43),
            'code_challenge_method' => 'plain',
            'nonce' => 'nonce-123',
        ]));
    }


    public function testItRequiresPkceEvenForConfidentialClients(): void
    {
        $grant = $this->createGrant(confidential: true);
        $this->expectException(OAuthServerException::class);

        $grant->validateAuthorizationRequest($this->authorizationRequest([
            'response_type' => 'code',
            'client_id' => 'client-1',
            'redirect_uri' => 'https://client.example/callback',
            'scope' => 'openid',
            'nonce' => 'nonce-123',
        ]));
    }

    public function testItRejectsNonceLongerThanConfiguredLimit(): void
    {
        $grant = $this->createGrant();
        $this->expectException(OAuthServerException::class);

        $grant->validateAuthorizationRequest($this->authorizationRequest([
            'response_type' => 'code',
            'client_id' => 'client-1',
            'redirect_uri' => 'https://client.example/callback',
            'scope' => 'openid',
            'code_challenge' => str_repeat('A', 43),
            'code_challenge_method' => 'S256',
            'nonce' => str_repeat('n', 257),
        ]));
    }

    public function testItRejectsRequestsWithoutOpenIdScope(): void
    {
        $grant = $this->createGrant();
        $this->expectException(OAuthServerException::class);

        $grant->validateAuthorizationRequest($this->authorizationRequest([
            'response_type' => 'code',
            'client_id' => 'client-1',
            'redirect_uri' => 'https://client.example/callback',
            'scope' => 'profile',
            'code_challenge' => str_repeat('A', 43),
            'code_challenge_method' => 'S256',
            'nonce' => 'nonce-123',
        ]));
    }


    public function testItParsesNonNegativeMaxAge(): void
    {
        $grant = $this->createGrant();
        $authorizationRequest = $grant->validateAuthorizationRequest($this->authorizationRequest([
            'response_type' => 'code',
            'client_id' => 'client-1',
            'redirect_uri' => 'https://client.example/callback',
            'scope' => 'openid',
            'code_challenge' => str_repeat('A', 43),
            'code_challenge_method' => 'S256',
            'nonce' => 'nonce-123',
            'max_age' => '0',
        ]));

        self::assertInstanceOf(OidcAuthorizationRequest::class, $authorizationRequest);
        self::assertSame(0, $authorizationRequest->maxAge());
    }

    public function testItRejectsInvalidMaxAgeValues(): void
    {
        foreach (['-1', 'abc', '1.5', str_repeat('9', 40), ['60']] as $invalidMaxAge) {
            $grant = $this->createGrant();
            try {
                $grant->validateAuthorizationRequest($this->authorizationRequest([
                    'response_type' => 'code',
                    'client_id' => 'client-1',
                    'redirect_uri' => 'https://client.example/callback',
                    'scope' => 'openid',
                    'code_challenge' => str_repeat('A', 43),
                    'code_challenge_method' => 'S256',
                    'nonce' => 'nonce-123',
                    'max_age' => $invalidMaxAge,
                ]));
                self::fail('Expected invalid max_age to be rejected.');
            } catch (OAuthServerException) {
                self::assertTrue(true);
            }
        }
    }

    public function testOfflineAccessRequiresAnExplicitConsentPrompt(): void
    {
        $grant = $this->createGrant(offlineAccessEnabled: true);
        $this->expectException(OAuthServerException::class);
        $grant->validateAuthorizationRequest($this->authorizationRequest([
            'response_type' => 'code',
            'client_id' => 'client-1',
            'redirect_uri' => 'https://client.example/callback',
            'scope' => 'openid offline_access',
            'code_challenge' => str_repeat('A', 43),
            'code_challenge_method' => 'S256',
            'nonce' => 'nonce-123',
        ]));
    }

    public function testOfflineAccessAcceptsExplicitConsentPrompt(): void
    {
        $grant = $this->createGrant(offlineAccessEnabled: true);
        $request = $this->authorizationRequest([
            'response_type' => 'code',
            'client_id' => 'client-1',
            'redirect_uri' => 'https://client.example/callback',
            'scope' => 'openid offline_access',
            'code_challenge' => str_repeat('A', 43),
            'code_challenge_method' => 'S256',
            'nonce' => 'nonce-123',
            'prompt' => 'login consent',
        ]);
        self::assertInstanceOf(OidcAuthorizationRequest::class, $grant->validateAuthorizationRequest($request));
    }

    private function createGrant(bool $confidential = false, bool $offlineAccessEnabled = false): OidcAuthCodeGrant
    {
        $client = $this->createMock(ClientEntityInterface::class);
        $client->method('getIdentifier')->willReturn('client-1');
        $client->method('getRedirectUri')->willReturn('https://client.example/callback');
        $client->method('isConfidential')->willReturn($confidential);

        $clientRepository = $this->createMock(ClientRepositoryInterface::class);
        $clientRepository->method('getClientEntity')->with('client-1')->willReturn($client);

        $scopeRepository = $this->createMock(ScopeRepositoryInterface::class);
        $scopeRepository->method('getScopeEntityByIdentifier')->willReturnCallback(
            function (string $identifier): ScopeEntityInterface {
                $scope = $this->createMock(ScopeEntityInterface::class);
                $scope->method('getIdentifier')->willReturn($identifier);

                return $scope;
            },
        );

        $grant = new OidcAuthCodeGrant(
            $this->createMock(AuthCodeRepositoryInterface::class),
            $this->createMock(RefreshTokenRepositoryInterface::class),
            new DateInterval('PT5M'),
            new RequestScopedOidcContextProvider(new OidcRequestContext()),
            $offlineAccessEnabled,
        );
        $grant->setClientRepository($clientRepository);
        $grant->setScopeRepository($scopeRepository);
        $grant->setDefaultScope('');

        return $grant;
    }

    /** @param array<string, mixed> $query */
    private function authorizationRequest(array $query): ServerRequestInterface
    {
        $request = $this->createMock(ServerRequestInterface::class);
        $request->method('getQueryParams')->willReturn($query);
        $request->method('getServerParams')->willReturn([]);
        $request->method('getParsedBody')->willReturn([]);

        return $request;
    }
}
