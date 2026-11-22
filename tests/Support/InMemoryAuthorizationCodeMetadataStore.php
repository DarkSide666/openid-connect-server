<?php

declare(strict_types=1);

namespace DarkSide\OpenIdConnectServer\Tests\Support;

use DarkSide\OpenIdConnectServer\Transaction\AuthorizationCodeMetadata;
use DarkSide\OpenIdConnectServer\Transaction\AuthorizationCodeMetadataStoreInterface;

final class InMemoryAuthorizationCodeMetadataStore implements AuthorizationCodeMetadataStoreInterface
{
    /** @var array<string, AuthorizationCodeMetadata> */
    private array $items = [];

    public function store(string $authorizationCodeId, AuthorizationCodeMetadata $metadata): void
    {
        if (isset($this->items[$authorizationCodeId])) {
            throw new \LogicException('Duplicate authorization-code metadata.');
        }

        $this->items[$authorizationCodeId] = $metadata;
    }

    public function consume(string $authorizationCodeId): ?AuthorizationCodeMetadata
    {
        $metadata = $this->items[$authorizationCodeId] ?? null;
        unset($this->items[$authorizationCodeId]);

        if ($metadata !== null && $metadata->expiresAt <= new \DateTimeImmutable()) {
            return null;
        }

        return $metadata;
    }
}
