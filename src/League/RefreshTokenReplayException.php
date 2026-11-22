<?php

declare(strict_types=1);

namespace DarkSide\OpenIdConnectServer\League;

use RuntimeException;

final class RefreshTokenReplayException extends RuntimeException
{
    public function __construct(public readonly string $refreshTokenId)
    {
        parent::__construct('A previously consumed refresh token was presented.');
    }
}
