<?php

declare(strict_types=1);

namespace DarkSide\OpenIdConnectServer\Tests\Support;

use League\OAuth2\Server\Entities\RefreshTokenEntityInterface;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;

final class NullLeagueRefreshTokenRepository implements RefreshTokenRepositoryInterface
{
    public function getNewRefreshToken(): ?RefreshTokenEntityInterface
    {
        return null;
    }

    public function persistNewRefreshToken(RefreshTokenEntityInterface $refreshTokenEntity): void
    {
        throw new \LogicException('The OIDC Authorization Code flow must not persist refresh tokens.');
    }

    public function revokeRefreshToken(string $tokenId): void
    {
    }

    public function isRefreshTokenRevoked(string $tokenId): bool
    {
        // This test repository intentionally supports no refresh tokens.
        // Fail closed if League ever attempts to validate one.
        return true;
    }
}
