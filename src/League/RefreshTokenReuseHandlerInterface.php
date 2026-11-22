<?php

declare(strict_types=1);

namespace DarkSide\OpenIdConnectServer\League;

interface RefreshTokenReuseHandlerInterface
{
    /** Bind the following League token persistence to this token's stored family. */
    public function beginRotation(string $refreshTokenId): void;

    /** Clear request-local rotation state. */
    public function endRotation(): void;

    /** Atomically revoke the family associated with a known, previously consumed token identifier. */
    public function revokeFamilyForReusedToken(string $refreshTokenId): void;
}
