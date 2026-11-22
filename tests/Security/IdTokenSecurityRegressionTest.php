<?php

declare(strict_types=1);

namespace DarkSide\OpenIdConnectServer\Tests\Security;

use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Validation\Constraint\PermittedFor;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use PHPUnit\Framework\TestCase;
use DarkSide\OpenIdConnectServer\Identity\ArrayIdentity;
use DarkSide\OpenIdConnectServer\Key\SigningKey;
use DarkSide\OpenIdConnectServer\Tests\Support\RsaKeyPair;
use DarkSide\OpenIdConnectServer\Token\IdTokenIssuer;

final class IdTokenSecurityRegressionTest extends TestCase
{
    public function testIdTokenUsesOnlyExpectedRs256HeadersAndBindsAudienceToClient(): void
    {
        $key = RsaKeyPair::generate('security-regression-key');
        $issuer = new IdTokenIssuer('https://issuer.example.test', $key);

        $serialized = $issuer->issue(
            'client-alpha',
            new ArrayIdentity('stable-subject'),
            'nonce-alpha',
        );

        $configuration = $this->configuration($key);
        $token = $configuration->parser()->parse($serialized);

        self::assertSame('RS256', $token->headers()->get('alg'));
        self::assertSame('JWT', $token->headers()->get('typ'));
        self::assertSame('security-regression-key', $token->headers()->get('kid'));
        self::assertNull($token->headers()->get('jku'));
        self::assertNull($token->headers()->get('x5u'));
        self::assertSame('https://issuer.example.test', $token->claims()->get('iss'));
        self::assertSame('stable-subject', $token->claims()->get('sub'));
        self::assertSame('nonce-alpha', $token->claims()->get('nonce'));

        self::assertTrue($configuration->validator()->validate(
            $token,
            new SignedWith(new Sha256(), InMemory::plainText($key->publicKeyPem)),
            new PermittedFor('client-alpha'),
        ));
        self::assertFalse($configuration->validator()->validate(
            $token,
            new SignedWith(new Sha256(), InMemory::plainText($key->publicKeyPem)),
            new PermittedFor('client-beta'),
        ));
    }

    public function testModifiedIdTokenPayloadFailsSignatureValidation(): void
    {
        $key = RsaKeyPair::generate('tamper-test-key');
        $serialized = (new IdTokenIssuer('https://issuer.example.test', $key))
            ->issue('client-alpha', new ArrayIdentity('stable-subject'), 'nonce-alpha');

        $parts = explode('.', $serialized);
        self::assertCount(3, $parts);

        $payload = json_decode($this->base64UrlDecode($parts[1]), true, flags: JSON_THROW_ON_ERROR);
        $payload['sub'] = 'attacker-controlled-subject';
        $parts[1] = $this->base64UrlEncode(json_encode($payload, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES));
        $tampered = implode('.', $parts);

        $configuration = $this->configuration($key);
        $parsed = $configuration->parser()->parse($tampered);

        self::assertFalse($configuration->validator()->validate(
            $parsed,
            new SignedWith(new Sha256(), InMemory::plainText($key->publicKeyPem)),
        ));
    }

    public function testIssuedTokenDoesNotExposePrivateKeyMaterialInCompactRepresentation(): void
    {
        $key = RsaKeyPair::generate('private-material-test-key');
        $serialized = (new IdTokenIssuer('https://issuer.example.test', $key))
            ->issue('client-alpha', new ArrayIdentity('stable-subject'), 'nonce-alpha');

        self::assertStringNotContainsString('BEGIN PRIVATE KEY', $serialized);
        self::assertStringNotContainsString('BEGIN RSA PRIVATE KEY', $serialized);
        self::assertStringNotContainsString($key->privateKeyPem, $serialized);
    }

    private function configuration(SigningKey $key): Configuration
    {
        return Configuration::forAsymmetricSigner(
            new Sha256(),
            InMemory::plainText($key->privateKeyPem),
            InMemory::plainText($key->publicKeyPem),
        );
    }

    private function base64UrlDecode(string $value): string
    {
        $decoded = base64_decode(strtr($value, '-_', '+/') . str_repeat('=', (4 - strlen($value) % 4) % 4), true);
        self::assertNotFalse($decoded);

        return $decoded;
    }

    private function base64UrlEncode(string $value): string
    {
        return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
    }
}
