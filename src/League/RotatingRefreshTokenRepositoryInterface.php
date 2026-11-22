<?php

declare(strict_types=1);

namespace DarkSide\OpenIdConnectServer\League;

use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;

/** Host repository contract for durable refresh-token rotation and family tracking. */
interface RotatingRefreshTokenRepositoryInterface extends RefreshTokenRepositoryInterface, RefreshTokenReuseHandlerInterface
{
    /** Atomically consume an active token and distinguish replay from invalid/expired tokens. */
    public function consumeRefreshToken(string $refreshTokenId): RefreshTokenConsumptionResult;
}
