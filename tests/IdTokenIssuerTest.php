<?php

declare(strict_types=1);

namespace DarkSide\OpenIdConnectServer\Tests;

use DateTimeImmutable;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Validation\Constraint\IssuedBy;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use PHPUnit\Framework\TestCase;
use DarkSide\OpenIdConnectServer\Identity\ArrayIdentity;
use DarkSide\OpenIdConnectServer\Token\IdTokenIssuer;
use DarkSide\OpenIdConnectServer\Tests\Support\RsaKeyPair;

final class IdTokenIssuerTest extends TestCase
{
    public function testIssuesSignedIdTokenWithRequiredClaims(): void
    {
        $key = RsaKeyPair::generate();
        $now = new DateTimeImmutable('2026-01-02T03:04:05+00:00');
        $identity = new ArrayIdentity(
            'user-immutable-subject',
            ['name' => 'Example User', 'email' => 'user@example.test', 'email_verified' => true],
            $now->modify('-2 minutes'),
        );

        $issuer = new IdTokenIssuer('https://identity.example.test', $key, 300);
        $serialized = $issuer->issue('test-client', $identity, 'nonce-value', $now, ['openid', 'profile', 'email']);

        $verification = Configuration::forAsymmetricSigner(
            new Sha256(),
            InMemory::plainText($key->privateKeyPem),
            InMemory::plainText($key->publicKeyPem),
        );
        $token = $verification->parser()->parse($serialized);

        self::assertTrue($verification->validator()->validate(
            $token,
            new SignedWith(new Sha256(), InMemory::plainText($key->publicKeyPem)),
            new IssuedBy('https://identity.example.test'),
        ));

        self::assertSame('https://identity.example.test', $token->claims()->get('iss'));
        self::assertSame('user-immutable-subject', $token->claims()->get('sub'));
        $audience = $token->claims()->get('aud');
        self::assertTrue(
            $audience === 'test-client'
            || (is_array($audience) && in_array('test-client', $audience, true)),
        );
        self::assertSame('nonce-value', $token->claims()->get('nonce'));
        self::assertSame($now->getTimestamp(), $token->claims()->get('iat')->getTimestamp());
        self::assertSame($now->modify('+300 seconds')->getTimestamp(), $token->claims()->get('exp')->getTimestamp());
        self::assertSame('test-key-1', $token->headers()->get('kid'));
        self::assertSame('Example User', $token->claims()->get('name'));
        self::assertSame($now->modify('-2 minutes')->getTimestamp(), $token->claims()->get('auth_time'));
    }


    public function testNumericDateClaimsAreEncodedAsIntegerUnixTimestamps(): void
    {
        $key = RsaKeyPair::generate();
        $now = new DateTimeImmutable('2026-01-02T03:04:05.654321+00:00');
        $issuer = new IdTokenIssuer('https://identity.example.test', $key, 300);
        $serialized = $issuer->issue('test-client', new ArrayIdentity('subject'), 'nonce', $now);

        $segments = explode('.', $serialized);
        self::assertCount(3, $segments);
        $payloadJson = base64_decode(strtr($segments[1], '-_', '+/'), true);
        self::assertIsString($payloadJson);
        $payload = json_decode($payloadJson, true, 512, JSON_THROW_ON_ERROR);

        self::assertIsInt($payload['iat']);
        self::assertIsInt($payload['exp']);
        self::assertSame($now->getTimestamp(), $payload['iat']);
        self::assertSame($now->getTimestamp() + 300, $payload['exp']);
    }

    public function testStandardClaimsAreFilteredByGrantedScopes(): void
    {
        $key = RsaKeyPair::generate();
        $identity = new ArrayIdentity('subject-1', [
            'name' => 'Allowed Name',
            'email' => 'private@example.test',
            'email_verified' => true,
            'phone_number' => '+10000000000',
            'custom_role' => 'operator',
        ]);

        $issuer = new IdTokenIssuer('https://identity.example.test', $key);
        $token = Configuration::forAsymmetricSigner(
            new Sha256(),
            InMemory::plainText($key->privateKeyPem),
            InMemory::plainText($key->publicKeyPem),
        )->parser()->parse($issuer->issue('client', $identity, 'nonce', null, ['openid', 'profile']));

        self::assertSame('Allowed Name', $token->claims()->get('name'));
        self::assertNull($token->claims()->get('email'));
        self::assertNull($token->claims()->get('email_verified'));
        self::assertNull($token->claims()->get('phone_number'));
        self::assertSame('operator', $token->claims()->get('custom_role'), 'Custom claims remain the resolver policy responsibility.');
    }

    public function testMaxAgeRequiresFreshAuthenticationTimeAndEmitsAuthTime(): void
    {
        $key = RsaKeyPair::generate();
        $now = new DateTimeImmutable('2026-01-02T03:04:05+00:00');
        $identity = new ArrayIdentity('subject-1', [], $now->modify('-30 seconds'));
        $issuer = new IdTokenIssuer('https://identity.example.test', $key);

        $token = Configuration::forAsymmetricSigner(
            new Sha256(),
            InMemory::plainText($key->privateKeyPem),
            InMemory::plainText($key->publicKeyPem),
        )->parser()->parse($issuer->issue('client', $identity, 'nonce', $now, ['openid'], 30));

        self::assertSame($now->modify('-30 seconds')->getTimestamp(), $token->claims()->get('auth_time'));
    }

    public function testMaxAgeRejectsMissingOrStaleAuthenticationTime(): void
    {
        $key = RsaKeyPair::generate();
        $issuer = new IdTokenIssuer('https://identity.example.test', $key);
        $now = new DateTimeImmutable('2026-01-02T03:04:05+00:00');

        try {
            $issuer->issue('client', new ArrayIdentity('subject'), 'nonce', $now, ['openid'], 60);
            self::fail('Expected missing auth_time to be rejected.');
        } catch (\InvalidArgumentException $exception) {
            self::assertStringContainsString('auth_time claim is required', $exception->getMessage());
        }

        try {
            $issuer->issue('client', new ArrayIdentity('subject', [], $now->modify('-61 seconds')), 'nonce', $now, ['openid'], 60);
            self::fail('Expected stale authentication to be rejected.');
        } catch (\InvalidArgumentException $exception) {
            self::assertStringContainsString('older than the requested max_age', $exception->getMessage());
        }
    }

    public function testRejectsFutureAuthTimeAndInvalidNonceLength(): void
    {
        $key = RsaKeyPair::generate();
        $issuer = new IdTokenIssuer('https://identity.example.test', $key);
        $now = new DateTimeImmutable('2026-01-02T03:04:05+00:00');

        try {
            $issuer->issue('client', new ArrayIdentity('subject', [], $now->modify('+1 second')), 'nonce', $now);
            self::fail('Expected future auth_time to be rejected.');
        } catch (\InvalidArgumentException $exception) {
            self::assertStringContainsString('must not be in the future', $exception->getMessage());
        }

        $this->expectException(\InvalidArgumentException::class);
        $issuer->issue('client', new ArrayIdentity('subject'), str_repeat('n', 257));
    }


    public function testRejectsIncorrectStandardClaimTypes(): void
    {
        $key = RsaKeyPair::generate();
        $issuer = new IdTokenIssuer('https://identity.example.test', $key);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('OIDC claim "email_verified" must be a boolean.');
        $issuer->issue('client', new ArrayIdentity('subject', ['email_verified' => 'yes']), 'nonce', null, ['openid', 'email']);
    }

    public function testRejectsNonJsonCompatibleCustomClaimValues(): void
    {
        $key = RsaKeyPair::generate();
        $issuer = new IdTokenIssuer('https://identity.example.test', $key);

        $this->expectException(\InvalidArgumentException::class);
        $issuer->issue('client', new ArrayIdentity('subject', ['bad' => new \stdClass()]), 'nonce');
    }

    public function testRejectsIdentityTryingToOverrideProtocolClaims(): void
    {
        $key = RsaKeyPair::generate();
        $issuer = new IdTokenIssuer('https://identity.example.test', $key);
        $identity = new ArrayIdentity('subject', ['iss' => 'https://attacker.example']);

        $this->expectException(\InvalidArgumentException::class);
        $issuer->issue('client', $identity, 'nonce');
    }

    public function testRejectsIssuerContainingQueryOrFragment(): void
    {
        $key = RsaKeyPair::generate();

        foreach ([
            'https://identity.example.test?tenant=one',
            'https://identity.example.test#fragment',
            'https://user:pass@identity.example.test',
        ] as $issuer) {
            try {
                new IdTokenIssuer($issuer, $key);
                self::fail(sprintf('Expected invalid issuer "%s" to be rejected.', $issuer));
            } catch (\InvalidArgumentException) {
                self::assertTrue(true);
            }
        }
    }

    public function testRejectsEmptyNonce(): void
    {
        $key = RsaKeyPair::generate();
        $issuer = new IdTokenIssuer('https://identity.example.test', $key);

        $this->expectException(\InvalidArgumentException::class);
        $issuer->issue('client', new ArrayIdentity('subject'), '');
    }
}
