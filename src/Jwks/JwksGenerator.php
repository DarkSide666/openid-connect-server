<?php

declare(strict_types=1);

namespace DarkSide\OpenIdConnectServer\Jwks;

use DarkSide\OpenIdConnectServer\Key\SigningKey;
use DarkSide\OpenIdConnectServer\Key\SigningKeySet;
use DarkSide\OpenIdConnectServer\Key\VerificationKey;

final readonly class JwksGenerator
{
    private SigningKeySet $keySet;

    public function __construct(SigningKey|SigningKeySet $keys)
    {
        $this->keySet = $keys instanceof SigningKey ? new SigningKeySet($keys) : $keys;
    }

    /** @return array{keys: list<array{kty: string, use: string, alg: string, kid: string, n: string, e: string}>} */
    public function generate(): array
    {
        return ['keys' => array_map(self::toJwk(...), $this->keySet->verificationKeys())];
    }

    /** @return array{kty: string, use: string, alg: string, kid: string, n: string, e: string} */
    private static function toJwk(VerificationKey $key): array
    {
        $resource = openssl_pkey_get_public($key->publicKeyPem);
        if ($resource === false) {
            throw new \RuntimeException('Unable to load a configured public key.');
        }

        $details = openssl_pkey_get_details($resource);
        if ($details === false || ($details['type'] ?? null) !== OPENSSL_KEYTYPE_RSA || !isset($details['rsa']['n'], $details['rsa']['e'])) {
            throw new \RuntimeException('A configured public key cannot be represented as an RSA JWK.');
        }

        return [
            'kty' => 'RSA', 'use' => 'sig', 'alg' => 'RS256', 'kid' => $key->keyId,
            'n' => self::base64UrlEncode($details['rsa']['n']),
            'e' => self::base64UrlEncode($details['rsa']['e']),
        ];
    }

    private static function base64UrlEncode(string $value): string
    {
        return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
    }
}
