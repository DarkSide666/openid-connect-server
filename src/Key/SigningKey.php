<?php

declare(strict_types=1);

namespace DarkSide\OpenIdConnectServer\Key;

final readonly class SigningKey
{
    public function __construct(
        public string $keyId,
        public string $privateKeyPem,
        public string $publicKeyPem,
    ) {
        if ($keyId === '' || preg_match('/^[A-Za-z0-9._-]{1,128}$/D', $keyId) !== 1) {
            throw new \InvalidArgumentException('The key ID must contain 1-128 URL-safe characters.');
        }

        $private = openssl_pkey_get_private($privateKeyPem);
        if ($private === false) {
            throw new \InvalidArgumentException('The private signing key is not a valid PEM key.');
        }

        $privateDetails = openssl_pkey_get_details($private);
        if ($privateDetails === false || ($privateDetails['type'] ?? null) !== OPENSSL_KEYTYPE_RSA) {
            throw new \InvalidArgumentException('RS256 requires an RSA private key.');
        }

        if (($privateDetails['bits'] ?? 0) < 2048) {
            throw new \InvalidArgumentException('RSA signing keys must be at least 2048 bits.');
        }

        $public = openssl_pkey_get_public($publicKeyPem);
        if ($public === false) {
            throw new \InvalidArgumentException('The public verification key is not a valid PEM key.');
        }

        $publicDetails = openssl_pkey_get_details($public);
        if ($publicDetails === false || ($publicDetails['type'] ?? null) !== OPENSSL_KEYTYPE_RSA) {
            throw new \InvalidArgumentException('The public key must be an RSA public key.');
        }

        if (
            !isset($privateDetails['rsa']['n'], $privateDetails['rsa']['e'], $publicDetails['rsa']['n'], $publicDetails['rsa']['e'])
            || !hash_equals($privateDetails['rsa']['n'], $publicDetails['rsa']['n'])
            || !hash_equals($privateDetails['rsa']['e'], $publicDetails['rsa']['e'])
        ) {
            throw new \InvalidArgumentException('The configured private and public keys do not form a matching pair.');
        }
    }
}
