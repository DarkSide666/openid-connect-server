<?php

declare(strict_types=1);

namespace DarkSide\OpenIdConnectServer\Tests\Support;

use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;

final class InMemoryLeagueAccessTokenRepository implements AccessTokenRepositoryInterface
{
    /** @var array<string, AccessTokenEntityInterface> */
    private array $items = [];

    /** @var array<string, true> */
    private array $revoked = [];

    public function __construct(private readonly AccessTokenEntityInterface $newAccessToken)
    {
    }

    public function getNewToken(
        ClientEntityInterface $clientEntity,
        array $scopes,
        ?string $userIdentifier = null,
    ): AccessTokenEntityInterface {
        return $this->newAccessToken;
    }

    public function persistNewAccessToken(AccessTokenEntityInterface $accessTokenEntity): void
    {
        $this->items[$accessTokenEntity->getIdentifier()] = $accessTokenEntity;
    }

    public function revokeAccessToken(string $tokenId): void
    {
        $this->revoked[$tokenId] = true;
    }

    public function isAccessTokenRevoked(string $tokenId): bool
    {
        return isset($this->revoked[$tokenId]);
    }
}
