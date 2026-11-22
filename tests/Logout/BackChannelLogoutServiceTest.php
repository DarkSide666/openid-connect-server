<?php

declare(strict_types=1);

namespace DarkSide\OpenIdConnectServer\Tests\Logout;

use DateTimeImmutable;
use PHPUnit\Framework\TestCase;
use DarkSide\OpenIdConnectServer\Key\VerificationKey;
use DarkSide\OpenIdConnectServer\Logout\BackChannelLogoutDeliveryInterface;
use DarkSide\OpenIdConnectServer\Logout\BackChannelLogoutService;
use DarkSide\OpenIdConnectServer\Logout\LogoutClientStoreInterface;
use DarkSide\OpenIdConnectServer\Logout\LogoutTokenIssuer;
use DarkSide\OpenIdConnectServer\Logout\LogoutTokenReplayStoreInterface;
use DarkSide\OpenIdConnectServer\Logout\LogoutTokenValidator;
use DarkSide\OpenIdConnectServer\Tests\Support\RsaKeyPair;

final class BackChannelLogoutServiceTest extends TestCase
{
    public function testDeliversSignedLogoutTokenBoundToRegisteredClientAndSession(): void
    {
        $key = RsaKeyPair::generate();
        $clients = new class () implements LogoutClientStoreInterface {
            public function recipients(string $subject, ?string $sessionId): iterable
            {
                TestCase::assertSame('subject-1', $subject);
                TestCase::assertSame('session-1', $sessionId);
                yield ['client_id' => 'rp-1', 'logout_uri' => 'https://rp.example.test/logout', 'session_required' => true];
            }
        };
        $delivery = new class () implements BackChannelLogoutDeliveryInterface {
            /** @var list<array{client_id:string,logout_uri:string,logout_token:string}> */
            public array $requests = [];

            public function deliver(string $clientId, string $logoutUri, string $logoutToken): void
            {
                $this->requests[] = ['client_id' => $clientId, 'logout_uri' => $logoutUri, 'logout_token' => $logoutToken];
            }
        };
        $service = new BackChannelLogoutService(
            $clients,
            $delivery,
            new LogoutTokenIssuer('https://issuer.example.test', $key),
        );
        $service->notify('subject-1', 'session-1');

        self::assertCount(1, $delivery->requests);
        self::assertSame('https://rp.example.test/logout', $delivery->requests[0]['logout_uri']);
        $replayStore = new class () implements LogoutTokenReplayStoreInterface {
            public function claim(string $issuer, string $clientId, string $tokenId, DateTimeImmutable $expiresAt): bool
            {
                return true;
            }
        };
        $claims = (new LogoutTokenValidator(
            'https://issuer.example.test',
            'rp-1',
            [new VerificationKey($key->keyId, $key->publicKeyPem)],
            $replayStore,
        ))->validate($delivery->requests[0]['logout_token']);
        self::assertSame('subject-1', $claims['sub']);
        self::assertSame('session-1', $claims['sid']);
    }

    public function testDoesNotSendSessionRequiredLogoutWithoutSessionId(): void
    {
        $key = RsaKeyPair::generate();
        $clients = new class () implements LogoutClientStoreInterface {
            public function recipients(string $subject, ?string $sessionId): iterable
            {
                yield ['client_id' => 'rp-1', 'logout_uri' => 'https://rp.example.test/logout', 'session_required' => true];
            }
        };
        $delivery = new class () implements BackChannelLogoutDeliveryInterface {
            public int $calls = 0;
            public function deliver(string $clientId, string $logoutUri, string $logoutToken): void
            {
                $this->calls++;
            }
        };
        (new BackChannelLogoutService($clients, $delivery, new LogoutTokenIssuer('https://issuer.example.test', $key)))
            ->notify('subject-1');

        self::assertSame(0, $delivery->calls);
    }
}
