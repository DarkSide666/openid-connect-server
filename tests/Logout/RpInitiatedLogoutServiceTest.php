<?php

declare(strict_types=1);

namespace DarkSide\OpenIdConnectServer\Tests\Logout;

use DateTimeImmutable;
use PHPUnit\Framework\TestCase;
use DarkSide\OpenIdConnectServer\Identity\ArrayIdentity;
use DarkSide\OpenIdConnectServer\Key\VerificationKey;
use DarkSide\OpenIdConnectServer\Logout\IdTokenHintValidator;
use DarkSide\OpenIdConnectServer\Logout\RpInitiatedLogoutRequest;
use DarkSide\OpenIdConnectServer\Logout\RpInitiatedLogoutService;
use DarkSide\OpenIdConnectServer\Tests\Support\RsaKeyPair;
use DarkSide\OpenIdConnectServer\Token\IdTokenIssuer;

final class RpInitiatedLogoutServiceTest extends TestCase
{
    public function testValidatesHintAndExactRegisteredPostLogoutRedirect(): void
    {
        $key = RsaKeyPair::generate();
        $issuedAt = new DateTimeImmutable('-2 hours');
        $hint = (new IdTokenIssuer('https://issuer.example.test', $key))
            ->issue('rp-client', new ArrayIdentity('subject-1'), 'nonce', $issuedAt);
        $service = new RpInitiatedLogoutService(new IdTokenHintValidator(
            'https://issuer.example.test',
            [new VerificationKey($key->keyId, $key->publicKeyPem)],
        ));
        $request = new RpInitiatedLogoutRequest(
            $hint,
            'rp-client',
            'https://rp.example.test/signed-out',
            'opaque-state',
        );
        $result = $service->validate($request, ['https://rp.example.test/signed-out']);
        self::assertSame('subject-1', $result['sub']);
        self::assertSame('opaque-state', $result['state']);

        $this->expectException(\InvalidArgumentException::class);
        $service->validate(
            new RpInitiatedLogoutRequest($hint, 'rp-client', 'https://attacker.example.test', 'state'),
            ['https://rp.example.test/signed-out'],
        );
    }
}
