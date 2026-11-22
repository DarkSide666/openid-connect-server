<?php

declare(strict_types=1);

namespace DarkSide\OpenIdConnectServer\Logout;

use DateInterval;
use DateTimeImmutable;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use DarkSide\OpenIdConnectServer\Key\SigningKey;

final readonly class LogoutTokenIssuer
{
    public function __construct(
        private string $issuer,
        private SigningKey $key,
        private int $lifetimeSeconds = 120,
    ) {
        $issuerParts = parse_url($issuer);
        if (
            !filter_var($issuer, FILTER_VALIDATE_URL) || !is_array($issuerParts)
            || strtolower((string) ($issuerParts['scheme'] ?? '')) !== 'https' || empty($issuerParts['host'])
            || isset($issuerParts['user']) || isset($issuerParts['pass']) || isset($issuerParts['fragment'])
            || $key->privateKeyPem === '' || $key->publicKeyPem === ''
            || $lifetimeSeconds < 1 || $lifetimeSeconds > 600
        ) {
            throw new \InvalidArgumentException('Logout Token lifetime must be between 1 and 600 seconds.');
        }
    }

    public function issue(string $clientId, ?string $subject, ?string $sessionId, ?DateTimeImmutable $now = null): string
    {
        if (
            $clientId === '' || ($subject === null && $sessionId === null)
            || ($subject !== null && $subject === '') || ($sessionId !== null && $sessionId === '')
        ) {
            throw new \InvalidArgumentException('A client and at least one logout identifier are required.');
        }
        if ($this->issuer === '' || $this->key->privateKeyPem === '' || $this->key->publicKeyPem === '') {
            throw new \LogicException('Logout Token signing configuration is invalid.');
        }
        $now ??= new DateTimeImmutable();
        $configuration = Configuration::forAsymmetricSigner(
            new Sha256(),
            InMemory::plainText($this->key->privateKeyPem),
            InMemory::plainText($this->key->publicKeyPem),
        );
        $builder = $configuration->builder()
            ->issuedBy($this->issuer)
            ->permittedFor($clientId)
            ->issuedAt($now)
            ->expiresAt($now->add(new DateInterval('PT' . $this->lifetimeSeconds . 'S')))
            ->identifiedBy(bin2hex(random_bytes(16)))
            ->withHeader('kid', $this->key->keyId)
            ->withHeader('typ', 'logout+jwt')
            ->withClaim('events', ['http://schemas.openid.net/event/backchannel-logout' => new \stdClass()]);
        if ($subject !== null) {
            $builder = $builder->relatedTo($subject);
        }
        if ($sessionId !== null) {
            $builder = $builder->withClaim('sid', $sessionId);
        }

        return $builder->getToken($configuration->signer(), $configuration->signingKey())->toString();
    }
}
