<?php

declare(strict_types=1);

/*
 * Demonstration only. Do not generate production keys on each request.
 * Store private keys outside the web root and load them from a secret-managed
 * location with restrictive filesystem permissions.
 */

require dirname(__DIR__) . '/vendor/autoload.php';

use DarkSide\OpenIdConnectServer\Identity\ArrayIdentity;
use DarkSide\OpenIdConnectServer\Key\SigningKey;
use DarkSide\OpenIdConnectServer\Token\IdTokenIssuer;

$privateKeyPath = getenv('OIDC_PRIVATE_KEY') ?: '';
$publicKeyPath = getenv('OIDC_PUBLIC_KEY') ?: '';
$keyId = getenv('OIDC_KEY_ID') ?: '';

if ($privateKeyPath === '' || $publicKeyPath === '' || $keyId === '') {
    throw new RuntimeException('Set OIDC_PRIVATE_KEY, OIDC_PUBLIC_KEY and OIDC_KEY_ID.');
}

$privateKey = file_get_contents($privateKeyPath);
$publicKey = file_get_contents($publicKeyPath);

if ($privateKey === false || $publicKey === false) {
    throw new RuntimeException('Unable to read configured signing keys.');
}

$signingKey = new SigningKey($keyId, $privateKey, $publicKey);
$issuer = new IdTokenIssuer('https://identity.example.test', $signingKey);

$identity = new ArrayIdentity(
    'immutable-user-subject',
    ['name' => 'Example User'],
    new DateTimeImmutable('now'),
);

echo $issuer->issue(
    'example-client',
    $identity,
    $validatedAuthorizationRequestNonce,
    null,
    ['openid', 'profile'],
) . PHP_EOL;
