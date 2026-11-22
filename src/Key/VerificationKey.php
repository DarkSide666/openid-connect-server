<?php

declare(strict_types=1);

namespace DarkSide\OpenIdConnectServer\Key;

final readonly class VerificationKey
{
    public function __construct(public string $keyId, public string $publicKeyPem)
    {
        if ($keyId === '' || preg_match('/^[A-Za-z0-9._-]{1,128}$/D', $keyId) !== 1) {
            throw new \InvalidArgumentException('The key ID must contain 1-128 URL-safe characters.');
        }

        $key = openssl_pkey_get_public($publicKeyPem);
        if ($key === false) {
            throw new \InvalidArgumentException('The verification key is not a valid PEM key.');
        }

        $details = openssl_pkey_get_details($key);
        if ($details === false || ($details['type'] ?? null) !== OPENSSL_KEYTYPE_RSA || ($details['bits'] ?? 0) < 2048) {
            throw new \InvalidArgumentException('Verification keys must be RSA keys of at least 2048 bits.');
        }
    }
}
