<?php

declare(strict_types=1);

namespace DarkSide\OpenIdConnectServer\Transaction;

use DateTimeImmutable;

final readonly class AuthorizationCodeMetadata
{
    public function __construct(
        public string $nonce,
        public DateTimeImmutable $expiresAt,
        public ?int $maxAge = null,
        public ?string $sessionId = null,
    ) {
        if ($nonce === '' || strlen($nonce) > 256) {
            throw new \InvalidArgumentException('The OIDC nonce must contain 1-256 bytes.');
        }

        if ($maxAge !== null && $maxAge < 0) {
            throw new \InvalidArgumentException('The OIDC max_age value must not be negative.');
        }
        if ($sessionId !== null && ($sessionId === '' || strlen($sessionId) > 255)) {
            throw new \InvalidArgumentException('The OIDC session ID must contain 1-255 bytes.');
        }
    }
}
