<?php

declare(strict_types=1);

namespace DarkSide\OpenIdConnectServer\Tests;

use PHPUnit\Framework\TestCase;
use DarkSide\OpenIdConnectServer\Jwks\JwksGenerator;
use DarkSide\OpenIdConnectServer\Key\SigningKeySet;
use DarkSide\OpenIdConnectServer\Key\VerificationKey;
use DarkSide\OpenIdConnectServer\Tests\Support\RsaKeyPair;

final class SigningKeySetTest extends TestCase
{
    public function testPublishesActiveAndRetiredPublicKeysForRotation(): void
    {
        $active = RsaKeyPair::generate('active-key');
        $retired = RsaKeyPair::generate('retired-key');
        $retiredVerificationKey = new VerificationKey($retired->keyId, $retired->publicKeyPem);

        $jwks = (new JwksGenerator(new SigningKeySet($active, [$retiredVerificationKey])))->generate();

        self::assertSame(['active-key', 'retired-key'], array_column($jwks['keys'], 'kid'));
        foreach ($jwks['keys'] as $jwk) {
            self::assertArrayNotHasKey('d', $jwk);
        }
    }

    public function testRejectsAssociativeRetiredKeyCollection(): void
    {
        $active = RsaKeyPair::generate('active');
        $retired = RsaKeyPair::generate('retired');

        $this->expectException(\InvalidArgumentException::class);
        new SigningKeySet($active, ['retired' => new VerificationKey($retired->keyId, $retired->publicKeyPem)]);
    }

    public function testRejectsDuplicateKeyIds(): void
    {
        $active = RsaKeyPair::generate('duplicate');
        $retired = RsaKeyPair::generate('another-internal-id');
        $retiredVerificationKey = new VerificationKey('duplicate', $retired->publicKeyPem);

        $this->expectException(\InvalidArgumentException::class);
        new SigningKeySet($active, [$retiredVerificationKey]);
    }
}
