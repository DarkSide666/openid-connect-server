<?php

declare(strict_types=1);

namespace DarkSide\OpenIdConnectServer\Tests;

use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\ResourceServer;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\StreamInterface;
use DarkSide\OpenIdConnectServer\Endpoint\UserInfoEndpoint;
use DarkSide\OpenIdConnectServer\Identity\ArrayIdentity;
use DarkSide\OpenIdConnectServer\Identity\IdentityResolverInterface;

final class UserInfoEndpointTest extends TestCase
{
    public function testReturnsSubjectAndOnlyClaimsAllowedByGrantedScopes(): void
    {
        $request = $this->request('GET');
        $validatedRequest = $this->validatedRequest('user-123', 'client-456', ['openid', 'profile']);
        $resourceServer = $this->createMock(ResourceServer::class);
        $resourceServer->expects(self::once())
            ->method('validateAuthenticatedRequest')
            ->with($request)
            ->willReturn($validatedRequest);

        $resolver = $this->createMock(IdentityResolverInterface::class);
        $resolver->expects(self::once())
            ->method('resolve')
            ->with('user-123', 'client-456', ['openid', 'profile'])
            ->willReturn(new ArrayIdentity('stable-subject', [
                'name' => 'Example User',
                'email' => 'user@example.test',
                'email_verified' => true,
                'department' => 'Engineering',
            ]));

        [$response, $written] = $this->response();
        $endpoint = new UserInfoEndpoint($resourceServer, $resolver);

        $result = $endpoint->handle($request, $response);

        self::assertSame($response, $result);
        self::assertSame([
            'sub' => 'stable-subject',
            'name' => 'Example User',
            'department' => 'Engineering',
        ], json_decode($written(), true, flags: JSON_THROW_ON_ERROR));
    }

    public function testRejectsAccessTokenWithoutOpenIdScope(): void
    {
        $request = $this->request('GET');
        $validatedRequest = $this->validatedRequest('user-123', 'client-456', ['profile']);
        $resourceServer = $this->createMock(ResourceServer::class);
        $resourceServer->expects(self::once())
            ->method('validateAuthenticatedRequest')
            ->willReturn($validatedRequest);

        $resolver = $this->createMock(IdentityResolverInterface::class);
        $resolver->expects(self::never())->method('resolve');

        [$response, $written] = $this->response();
        $result = (new UserInfoEndpoint($resourceServer, $resolver))->handle($request, $response);

        self::assertSame($response, $result);
        self::assertSame(['error' => 'insufficient_scope'], json_decode($written(), true, flags: JSON_THROW_ON_ERROR));
    }

    public function testReturnsEmailClaimsOnlyWhenEmailScopeWasGranted(): void
    {
        $request = $this->request('GET');
        $validatedRequest = $this->validatedRequest('user-123', 'client-456', ['openid', 'email']);
        $resourceServer = $this->createMock(ResourceServer::class);
        $resourceServer->method('validateAuthenticatedRequest')->willReturn($validatedRequest);

        $resolver = $this->createMock(IdentityResolverInterface::class);
        $resolver->method('resolve')->willReturn(new ArrayIdentity('stable-subject', [
            'email' => 'user@example.test',
            'email_verified' => true,
        ]));

        [$response, $written] = $this->response();
        (new UserInfoEndpoint($resourceServer, $resolver))->handle($request, $response);

        self::assertSame([
            'sub' => 'stable-subject',
            'email' => 'user@example.test',
            'email_verified' => true,
        ], json_decode($written(), true, flags: JSON_THROW_ON_ERROR));
    }

    public function testInvalidBearerTokenUsesLeagueErrorAndDisablesCaching(): void
    {
        $request = $this->request('GET');
        $resourceServer = $this->createMock(ResourceServer::class);
        $resourceServer->method('validateAuthenticatedRequest')
            ->willThrowException(OAuthServerException::accessDenied('Invalid access token'));
        $resolver = $this->createMock(IdentityResolverInterface::class);
        $resolver->expects(self::never())->method('resolve');

        $headers = [];
        $written = '';
        $stream = $this->createMock(StreamInterface::class);
        $stream->method('write')->willReturnCallback(static function (string $data) use (&$written): int {
            $written .= $data;
            return strlen($data);
        });
        $response = $this->createMock(ResponseInterface::class);
        $response->method('getBody')->willReturn($stream);
        $response->method('withStatus')->willReturnSelf();
        $response->method('withHeader')->willReturnCallback(static function (string $name, string|array $value) use (&$headers, $response): ResponseInterface {
            $headers[$name] = $value;
            return $response;
        });

        (new UserInfoEndpoint($resourceServer, $resolver))->handle($request, $response);

        self::assertSame('no-store', $headers['Cache-Control'] ?? null);
        self::assertSame('no-cache', $headers['Pragma'] ?? null);
        self::assertNotSame('', $written);
    }

    public function testRejectsTokenWithoutEndUserIdentifier(): void
    {
        $request = $this->request('GET');
        $validatedRequest = $this->validatedRequest(null, 'client-456', ['openid']);
        $resourceServer = $this->createMock(ResourceServer::class);
        $resourceServer->method('validateAuthenticatedRequest')->willReturn($validatedRequest);

        $resolver = $this->createMock(IdentityResolverInterface::class);
        $resolver->expects(self::never())->method('resolve');

        [$response, $written] = $this->response();
        (new UserInfoEndpoint($resourceServer, $resolver))->handle($request, $response);

        self::assertSame(['error' => 'access_denied'], json_decode($written(), true, flags: JSON_THROW_ON_ERROR));
    }

    public function testRejectsUnsupportedHttpMethodBeforeValidatingToken(): void
    {
        $request = $this->request('PUT');
        $resourceServer = $this->createMock(ResourceServer::class);
        $resourceServer->expects(self::never())->method('validateAuthenticatedRequest');
        $resolver = $this->createMock(IdentityResolverInterface::class);
        $resolver->expects(self::never())->method('resolve');

        [$response, $written] = $this->response();
        (new UserInfoEndpoint($resourceServer, $resolver))->handle($request, $response);

        self::assertSame(['error' => 'method_not_allowed'], json_decode($written(), true, flags: JSON_THROW_ON_ERROR));
    }

    public function testRejectsResolverAttemptToOverrideSubject(): void
    {
        $request = $this->request('GET');
        $validatedRequest = $this->validatedRequest('user-123', 'client-456', ['openid']);
        $resourceServer = $this->createMock(ResourceServer::class);
        $resourceServer->method('validateAuthenticatedRequest')->willReturn($validatedRequest);

        $resolver = $this->createMock(IdentityResolverInterface::class);
        $resolver->method('resolve')->willReturn(new ArrayIdentity('stable-subject', ['sub' => 'attacker-subject']));

        [$response] = $this->response();
        $this->expectException(\InvalidArgumentException::class);
        (new UserInfoEndpoint($resourceServer, $resolver))->handle($request, $response);
    }

    private function request(string $method): ServerRequestInterface
    {
        $request = $this->createMock(ServerRequestInterface::class);
        $request->method('getMethod')->willReturn($method);
        return $request;
    }

    /** @param list<string> $scopes */
    private function validatedRequest(?string $userId, string $clientId, array $scopes): ServerRequestInterface
    {
        $request = $this->createMock(ServerRequestInterface::class);
        $request->method('getAttribute')->willReturnCallback(
            static fn (string $name, mixed $default = null): mixed => match ($name) {
                'oauth_user_id' => $userId,
                'oauth_client_id' => $clientId,
                'oauth_scopes' => $scopes,
                default => $default,
            },
        );
        return $request;
    }

    /** @return array{ResponseInterface, callable(): string} */
    private function response(): array
    {
        $written = '';
        $stream = $this->createMock(StreamInterface::class);
        $stream->method('write')->willReturnCallback(static function (string $data) use (&$written): int {
            $written .= $data;
            return strlen($data);
        });

        $response = $this->createMock(ResponseInterface::class);
        $response->method('getBody')->willReturn($stream);
        $response->method('withStatus')->willReturnSelf();
        $response->method('withHeader')->willReturnSelf();

        return [$response, static function () use (&$written): string {
            return $written;
        }];
    }
}
