<?php

declare(strict_types=1);

namespace DarkSide\OpenIdConnectServer\Tests;

use PHPUnit\Framework\TestCase;
use DarkSide\OpenIdConnectServer\Key\SigningKey;
use DarkSide\OpenIdConnectServer\Tests\Support\RsaKeyPair;

final class SigningKeyTest extends TestCase
{
    public function testRejectsMismatchedPrivateAndPublicKeys(): void
    {
        $first = RsaKeyPair::generate('first');
        $second = RsaKeyPair::generate('second');

        $this->expectException(\InvalidArgumentException::class);
        new SigningKey('mismatch', $first->privateKeyPem, $second->publicKeyPem);
    }
}
