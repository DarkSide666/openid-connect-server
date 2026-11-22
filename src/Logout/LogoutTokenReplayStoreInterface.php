<?php

declare(strict_types=1);

namespace DarkSide\OpenIdConnectServer\Logout;

interface LogoutTokenReplayStoreInterface
{
    /** Atomically reserve an issuer/client/token tuple until expiry; false means replay. */
    public function claim(string $issuer, string $clientId, string $tokenId, \DateTimeImmutable $expiresAt): bool;
}
