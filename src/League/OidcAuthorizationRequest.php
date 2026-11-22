<?php

declare(strict_types=1);

namespace DarkSide\OpenIdConnectServer\League;

use League\OAuth2\Server\RequestTypes\AuthorizationRequest;

final class OidcAuthorizationRequest extends AuthorizationRequest
{
    private ?string $nonce = null;
    private ?int $maxAge = null;

    public function setNonce(string $nonce): void
    {
        if ($nonce === '' || strlen($nonce) > 256) {
            throw new \InvalidArgumentException('The OIDC nonce must contain 1-256 bytes.');
        }

        $this->nonce = $nonce;
    }

    public function nonce(): string
    {
        return $this->nonce ?? throw new \LogicException('The OIDC authorization request has no nonce.');
    }

    public function setMaxAge(?int $maxAge): void
    {
        if ($maxAge !== null && $maxAge < 0) {
            throw new \InvalidArgumentException('The OIDC max_age value must not be negative.');
        }

        $this->maxAge = $maxAge;
    }

    public function maxAge(): ?int
    {
        return $this->maxAge;
    }
}
