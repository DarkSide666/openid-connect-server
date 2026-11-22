<?php

declare(strict_types=1);

namespace DarkSide\OpenIdConnectServer\Tests\Support;

use DarkSide\OpenIdConnectServer\Key\SigningKey;

final class RsaKeyPair
{
    public static function generate(string $kid = 'test-key-1'): SigningKey
    {
        $resource = openssl_pkey_new([
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
            'private_key_bits' => 2048,
        ]);

        if ($resource === false) {
            throw new \RuntimeException('Unable to generate test RSA key.');
        }

        if (!openssl_pkey_export($resource, $privatePem)) {
            throw new \RuntimeException('Unable to export test private key.');
        }

        $details = openssl_pkey_get_details($resource);
        if ($details === false || !isset($details['key'])) {
            throw new \RuntimeException('Unable to export test public key.');
        }

        return new SigningKey($kid, $privatePem, $details['key']);
    }
}
