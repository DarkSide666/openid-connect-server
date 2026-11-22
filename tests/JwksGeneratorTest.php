<?php

declare(strict_types=1);

namespace DarkSide\OpenIdConnectServer\Tests;

use PHPUnit\Framework\TestCase;
use DarkSide\OpenIdConnectServer\Jwks\JwksGenerator;
use DarkSide\OpenIdConnectServer\Tests\Support\RsaKeyPair;

final class JwksGeneratorTest extends TestCase
{
    public function testPublishesOnlyPublicRsaParameters(): void
    {
        $key = RsaKeyPair::generate('rotation-key-a');
        $jwks = (new JwksGenerator($key))->generate();

        self::assertCount(1, $jwks['keys']);
        self::assertSame('RSA', $jwks['keys'][0]['kty']);
        self::assertSame('RS256', $jwks['keys'][0]['alg']);
        self::assertSame('rotation-key-a', $jwks['keys'][0]['kid']);
        self::assertArrayHasKey('n', $jwks['keys'][0]);
        self::assertArrayHasKey('e', $jwks['keys'][0]);
        self::assertArrayNotHasKey('d', $jwks['keys'][0]);
        self::assertArrayNotHasKey('privateKeyPem', $jwks['keys'][0]);
    }
}
