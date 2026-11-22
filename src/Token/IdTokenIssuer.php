<?php

declare(strict_types=1);

namespace DarkSide\OpenIdConnectServer\Token;

use DateInterval;
use DateTimeImmutable;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use DarkSide\OpenIdConnectServer\Identity\IdentityInterface;
use DarkSide\OpenIdConnectServer\Identity\ScopeClaimFilter;
use DarkSide\OpenIdConnectServer\Key\SigningKey;

final readonly class IdTokenIssuer
{
    private const RESERVED_CLAIMS = [
        'iss', 'sub', 'aud', 'exp', 'iat', 'nbf', 'jti', 'nonce',
        'azp', 'at_hash', 'c_hash', 's_hash', 'auth_time', 'acr', 'amr', 'sid',
    ];

    public function __construct(
        private string $issuer,
        private SigningKey $signingKey,
        private int $lifetimeSeconds = 300,
        private ScopeClaimFilter $scopeClaimFilter = new ScopeClaimFilter(),
    ) {
        $issuerParts = parse_url($issuer);
        if (
            !filter_var($issuer, FILTER_VALIDATE_URL)
            || !is_array($issuerParts)
            || strtolower((string) ($issuerParts['scheme'] ?? '')) !== 'https'
            || empty($issuerParts['host'])
            || isset($issuerParts['user'])
            || isset($issuerParts['pass'])
            || isset($issuerParts['query'])
            || isset($issuerParts['fragment'])
        ) {
            throw new \InvalidArgumentException('The OIDC issuer must be an absolute HTTPS URL without credentials, query or fragment.');
        }

        if ($lifetimeSeconds < 1 || $lifetimeSeconds > 3600) {
            throw new \InvalidArgumentException('ID Token lifetime must be between 1 and 3600 seconds.');
        }
    }

    /**
     * @param list<string> $grantedScopes
     */
    public function issue(
        string $clientId,
        IdentityInterface $identity,
        string $nonce,
        ?DateTimeImmutable $now = null,
        array $grantedScopes = [],
        ?int $maxAge = null,
        ?string $sessionId = null,
    ): string {
        if ($clientId === '') {
            throw new \InvalidArgumentException('The client ID must not be empty.');
        }

        if ($nonce === '' || strlen($nonce) > 256) {
            throw new \InvalidArgumentException('The OIDC nonce must contain 1-256 bytes.');
        }

        if ($maxAge !== null && $maxAge < 0) {
            throw new \InvalidArgumentException('The max_age value must not be negative.');
        }
        if ($sessionId !== null && ($sessionId === '' || strlen($sessionId) > 255)) {
            throw new \InvalidArgumentException('The session ID must contain 1-255 bytes.');
        }

        $subject = $identity->subject();
        if (strlen($subject) > 255 || preg_match('/^[\x21-\x7E]+$/D', $subject) !== 1) {
            throw new \InvalidArgumentException('The identity subject must contain 1-255 printable ASCII characters.');
        }

        $now ??= new DateTimeImmutable('now');
        $authTime = $identity->authTime();
        if ($authTime !== null && $authTime > $now) {
            throw new \InvalidArgumentException('The authentication time must not be in the future.');
        }

        if ($maxAge !== null) {
            if ($authTime === null) {
                throw new \InvalidArgumentException('An auth_time claim is required when max_age is requested.');
            }

            if (($now->getTimestamp() - $authTime->getTimestamp()) > $maxAge) {
                throw new \InvalidArgumentException('The authentication is older than the requested max_age. The host application must re-authenticate the user.');
            }
        }

        $privateKeyPem = $this->signingKey->privateKeyPem;
        $publicKeyPem = $this->signingKey->publicKeyPem;
        $issuer = $this->issuer;
        if ($privateKeyPem === '' || $publicKeyPem === '' || $issuer === '') {
            throw new \LogicException('The issuer and signing key material must not be empty.');
        }

        // Lcobucci JWT formats registered date claims from DateTimeImmutable
        // with microsecond precision. Normalize to whole seconds so NumericDate
        // values are serialized as JSON integers for broad RP interoperability.
        $issuedAt = $now->setTime(
            (int) $now->format('H'),
            (int) $now->format('i'),
            (int) $now->format('s'),
            0,
        );
        $expiresAt = $issuedAt->add(new DateInterval('PT' . $this->lifetimeSeconds . 'S'));
        $jwtConfiguration = Configuration::forAsymmetricSigner(
            new Sha256(),
            InMemory::plainText($privateKeyPem),
            InMemory::plainText($publicKeyPem),
        );

        $builder = $jwtConfiguration->builder()
            ->issuedBy($issuer)
            ->permittedFor($clientId)
            ->relatedTo($subject)
            // Use the registered-claim APIs. The normalized DateTimeImmutable
            // instances have zero microseconds, so their NumericDate values encode
            // as whole-second JSON numbers.
            ->issuedAt($issuedAt)
            ->expiresAt($expiresAt)
            ->withHeader('kid', $this->signingKey->keyId)
            ->withHeader('typ', 'JWT')
            ->withClaim('nonce', $nonce);

        if ($authTime !== null) {
            $builder = $builder->withClaim('auth_time', $authTime->getTimestamp());
        }
        if ($sessionId !== null) {
            $builder = $builder->withClaim('sid', $sessionId);
        }

        $claims = $this->scopeClaimFilter->filter($identity->claims(), $grantedScopes);
        $this->validateStandardClaimTypes($claims);
        foreach ($claims as $name => $value) {
            if ($name === '' || in_array($name, self::RESERVED_CLAIMS, true)) {
                throw new \InvalidArgumentException(sprintf('Identity attempted to provide reserved or invalid claim "%s".', (string) $name));
            }

            if ($value !== null) {
                if (!$this->isJsonValue($value)) {
                    throw new \InvalidArgumentException(sprintf('Identity claim "%s" is not JSON-compatible.', $name));
                }

                $builder = $builder->withClaim($name, $value);
            }
        }

        return $builder->getToken($jwtConfiguration->signer(), $jwtConfiguration->signingKey())->toString();
    }

    /** @param array<string, mixed> $claims */
    private function validateStandardClaimTypes(array $claims): void
    {
        $stringClaims = [
            'name', 'family_name', 'given_name', 'middle_name', 'nickname',
            'preferred_username', 'profile', 'picture', 'website', 'gender',
            'birthdate', 'zoneinfo', 'locale', 'email', 'phone_number',
        ];

        foreach ($stringClaims as $claim) {
            if (isset($claims[$claim]) && !is_string($claims[$claim])) {
                throw new \InvalidArgumentException(sprintf('OIDC claim "%s" must be a string.', $claim));
            }
        }

        foreach (['email_verified', 'phone_number_verified'] as $claim) {
            if (isset($claims[$claim]) && !is_bool($claims[$claim])) {
                throw new \InvalidArgumentException(sprintf('OIDC claim "%s" must be a boolean.', $claim));
            }
        }

        if (isset($claims['updated_at']) && !is_int($claims['updated_at']) && !is_float($claims['updated_at'])) {
            throw new \InvalidArgumentException('OIDC claim "updated_at" must be a NumericDate.');
        }

        if (isset($claims['address']) && (!is_array($claims['address']) || array_is_list($claims['address']))) {
            throw new \InvalidArgumentException('OIDC claim "address" must be an object-shaped array.');
        }
    }

    private function isJsonValue(mixed $value): bool
    {
        if (is_null($value) || is_string($value) || is_bool($value) || is_int($value)) {
            return true;
        }

        if (is_float($value)) {
            return is_finite($value);
        }

        if (!is_array($value)) {
            return false;
        }

        foreach ($value as $item) {
            if (!$this->isJsonValue($item)) {
                return false;
            }
        }

        return true;
    }
}
