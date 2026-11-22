<?php

declare(strict_types=1);

namespace DarkSide\OpenIdConnectServer\Tests;

use DateTimeImmutable;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use PHPUnit\Framework\TestCase;
use DarkSide\OpenIdConnectServer\Identity\ArrayIdentity;
use DarkSide\OpenIdConnectServer\Jwks\JwksGenerator;
use DarkSide\OpenIdConnectServer\Key\SigningKeySet;
use DarkSide\OpenIdConnectServer\Key\VerificationKey;
use DarkSide\OpenIdConnectServer\Tests\Support\RsaKeyPair;
use DarkSide\OpenIdConnectServer\Token\IdTokenIssuer;

final class KeyRotationIntegrationTest extends TestCase
{
    public function testNewKeySignsTokensWhileJwksRetainsOldVerificationKey(): void
    {
        $oldKey = RsaKeyPair::generate('key-before-rotation');
        $newKey = RsaKeyPair::generate('key-after-rotation');
        $now = new DateTimeImmutable('2026-11-21T12:00:00+00:00');

        $oldToken = (new IdTokenIssuer('https://identity.example.test', $oldKey))
            ->issue('client-1', new ArrayIdentity('stable-subject'), 'nonce-old', $now);

        $rotatedSet = new SigningKeySet(
            $newKey,
            [new VerificationKey($oldKey->keyId, $oldKey->publicKeyPem)],
        );
        $jwks = (new JwksGenerator($rotatedSet))->generate();
        $publishedKids = array_column($jwks['keys'], 'kid');

        self::assertSame(['key-after-rotation', 'key-before-rotation'], $publishedKids);
        self::assertSame('RS256', $jwks['keys'][0]['alg']);
        self::assertArrayNotHasKey('d', $jwks['keys'][0]);

        $newToken = (new IdTokenIssuer('https://identity.example.test', $newKey))
            ->issue('client-1', new ArrayIdentity('stable-subject'), 'nonce-new', $now);

        $parser = Configuration::forAsymmetricSigner(
            new Sha256(),
            InMemory::plainText($newKey->privateKeyPem),
            InMemory::plainText($newKey->publicKeyPem),
        )->parser();

        $parsedOldToken = $parser->parse($oldToken);
        $parsedNewToken = $parser->parse($newToken);

        self::assertSame('key-before-rotation', $parsedOldToken->headers()->get('kid'));
        self::assertSame('key-after-rotation', $parsedNewToken->headers()->get('kid'));

        $oldVerifier = Configuration::forAsymmetricSigner(
            new Sha256(),
            InMemory::plainText($newKey->privateKeyPem),
            InMemory::plainText($oldKey->publicKeyPem),
        );
        $newVerifier = Configuration::forAsymmetricSigner(
            new Sha256(),
            InMemory::plainText($newKey->privateKeyPem),
            InMemory::plainText($newKey->publicKeyPem),
        );

        self::assertTrue($oldVerifier->validator()->validate(
            $parsedOldToken,
            new SignedWith(new Sha256(), InMemory::plainText($oldKey->publicKeyPem)),
        ));
        self::assertTrue($newVerifier->validator()->validate(
            $parsedNewToken,
            new SignedWith(new Sha256(), InMemory::plainText($newKey->publicKeyPem)),
        ));
    }
}
