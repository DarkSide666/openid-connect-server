<?php

declare(strict_types=1);

namespace DarkSide\OpenIdConnectServer\Transaction;

final class OidcRequestContext
{
    private ?string $pendingNonce = null;
    private ?int $pendingMaxAge = null;
    private ?string $redeemedNonce = null;
    private ?int $redeemedMaxAge = null;
    private bool $refreshResponse = false;

    public function setRefreshResponse(bool $refreshResponse): void
    {
        $this->refreshResponse = $refreshResponse;
    }

    public function isRefreshResponse(): bool
    {
        return $this->refreshResponse;
    }

    public function setPendingNonce(string $nonce, ?int $maxAge = null): void
    {
        if ($this->pendingNonce !== null || $this->redeemedNonce !== null) {
            throw new \LogicException('OIDC request context is already in use.');
        }
        if ($nonce === '' || strlen($nonce) > 256 || ($maxAge !== null && $maxAge < 0)) {
            throw new \InvalidArgumentException('Invalid OIDC authorization transaction metadata.');
        }

        $this->pendingNonce = $nonce;
        $this->pendingMaxAge = $maxAge;
    }

    public function pendingNonce(): ?string
    {
        return $this->pendingNonce;
    }

    public function pendingMaxAge(): ?int
    {
        return $this->pendingMaxAge;
    }

    public function consumePendingNonce(): ?string
    {
        $nonce = $this->pendingNonce;
        $this->pendingNonce = null;

        return $nonce;
    }

    public function consumePendingMaxAge(): ?int
    {
        $maxAge = $this->pendingMaxAge;
        $this->pendingMaxAge = null;

        return $maxAge;
    }

    public function clearPendingNonce(): void
    {
        $this->pendingNonce = null;
        $this->pendingMaxAge = null;
    }

    public function setRedeemedNonce(string $nonce, ?int $maxAge = null): void
    {
        if ($this->redeemedNonce !== null) {
            throw new \LogicException('An OIDC nonce has already been attached to this token response.');
        }
        if ($nonce === '' || strlen($nonce) > 256 || ($maxAge !== null && $maxAge < 0)) {
            throw new \InvalidArgumentException('Invalid redeemed OIDC transaction metadata.');
        }

        $this->redeemedNonce = $nonce;
        $this->redeemedMaxAge = $maxAge;
    }

    public function consumeRedeemedNonce(): ?string
    {
        $nonce = $this->redeemedNonce;
        $this->redeemedNonce = null;

        return $nonce;
    }

    public function consumeRedeemedMaxAge(): ?int
    {
        $maxAge = $this->redeemedMaxAge;
        $this->redeemedMaxAge = null;

        return $maxAge;
    }
}
