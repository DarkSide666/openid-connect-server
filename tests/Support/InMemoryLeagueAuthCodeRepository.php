<?php

declare(strict_types=1);

namespace DarkSide\OpenIdConnectServer\Tests\Support;

use League\OAuth2\Server\Entities\AuthCodeEntityInterface;
use League\OAuth2\Server\Repositories\AuthCodeRepositoryInterface;

final class InMemoryLeagueAuthCodeRepository implements AuthCodeRepositoryInterface
{
    /** @var array<string, AuthCodeEntityInterface> */
    private array $items = [];

    /** @var array<string, true> */
    private array $revoked = [];

    public function __construct(private readonly AuthCodeEntityInterface $newAuthCode)
    {
    }

    public function getNewAuthCode(): AuthCodeEntityInterface
    {
        return $this->newAuthCode;
    }

    public function persistNewAuthCode(AuthCodeEntityInterface $authCodeEntity): void
    {
        $this->items[$authCodeEntity->getIdentifier()] = $authCodeEntity;
        unset($this->revoked[$authCodeEntity->getIdentifier()]);
    }

    public function revokeAuthCode(string $codeId): void
    {
        $this->revoked[$codeId] = true;
        unset($this->items[$codeId]);
    }

    public function isAuthCodeRevoked(string $codeId): bool
    {
        return isset($this->revoked[$codeId]);
    }
}
