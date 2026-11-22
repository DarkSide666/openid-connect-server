<?php

declare(strict_types=1);

namespace DarkSide\OpenIdConnectServer\Tests\Logout;

use DateTimeImmutable;
use PHPUnit\Framework\TestCase;
use DarkSide\OpenIdConnectServer\Key\VerificationKey;
use DarkSide\OpenIdConnectServer\Logout\LogoutTokenIssuer;
use DarkSide\OpenIdConnectServer\Logout\LogoutTokenReplayStoreInterface;
use DarkSide\OpenIdConnectServer\Logout\LogoutTokenValidator;
use DarkSide\OpenIdConnectServer\Tests\Support\RsaKeyPair;

final class LogoutTokenTest extends TestCase
{
    public function testIssuesAndValidatesLogoutTokenWithSubjectAndSession(): void
    {
        $key = RsaKeyPair::generate();
        $replayStore = new class () implements LogoutTokenReplayStoreInterface {
            /** @var array<string, true> */
            public array $seen = [];
            public function claim(string $issuer, string $clientId, string $tokenId, DateTimeImmutable $expiresAt): bool
            {
                $key = $issuer . '|' . $clientId . '|' . $tokenId;
                if (isset($this->seen[$key])) {
                    return false;
                }
                $this->seen[$key] = true;
                return true;
            }
        };
        $issuer = new LogoutTokenIssuer('https://issuer.example.test', $key);
        $validator = new LogoutTokenValidator(
            'https://issuer.example.test',
            'rp-client',
            [new VerificationKey($key->keyId, $key->publicKeyPem)],
            $replayStore,
        );
        $now = new DateTimeImmutable('2026-01-02T03:04:05+00:00');
        $jwt = $issuer->issue('rp-client', 'subject-1', 'session-1', $now);
        $claims = $validator->validate($jwt, $now->modify('+1 second'));
        self::assertSame('subject-1', $claims['sub']);
        self::assertSame('session-1', $claims['sid']);
        $this->expectException(\InvalidArgumentException::class);
        $validator->validate($jwt, $now->modify('+2 seconds'));
    }
}
