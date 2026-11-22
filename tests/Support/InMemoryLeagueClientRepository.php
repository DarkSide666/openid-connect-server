<?php

declare(strict_types=1);

namespace DarkSide\OpenIdConnectServer\Tests\Support;

use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;

final readonly class InMemoryLeagueClientRepository implements ClientRepositoryInterface
{
    /** @param array<string, ClientEntityInterface> $clients @param array<string, string> $clientSecrets */
    public function __construct(
        private array $clients,
        private array $clientSecrets,
    ) {
    }

    public function getClientEntity(string $clientIdentifier): ?ClientEntityInterface
    {
        return $this->clients[$clientIdentifier] ?? null;
    }

    public function validateClient(string $clientIdentifier, ?string $clientSecret, ?string $grantType): bool
    {
        return isset($this->clientSecrets[$clientIdentifier])
            && $clientSecret !== null
            && hash_equals($this->clientSecrets[$clientIdentifier], $clientSecret);
    }
}
