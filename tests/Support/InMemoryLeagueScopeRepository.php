<?php

declare(strict_types=1);

namespace DarkSide\OpenIdConnectServer\Tests\Support;

use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;

final readonly class InMemoryLeagueScopeRepository implements ScopeRepositoryInterface
{
    /** @param array<string, ScopeEntityInterface> $scopes */
    public function __construct(private array $scopes)
    {
    }

    public function getScopeEntityByIdentifier(?string $scopeIdentifier): ?ScopeEntityInterface
    {
        if ($scopeIdentifier === null || $scopeIdentifier === '') {
            return null;
        }

        return $this->scopes[$scopeIdentifier] ?? null;
    }

    /** @param list<ScopeEntityInterface> $scopes @return list<ScopeEntityInterface> */
    public function finalizeScopes(
        array $scopes,
        string $grantTypeId,
        ClientEntityInterface $clientEntity,
        ?string $userIdentifier = null,
        ?string $authCodeId = null,
    ): array {
        return $scopes;
    }
}
