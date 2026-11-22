<?php

declare(strict_types=1);

namespace DarkSide\OpenIdConnectServer\Transaction;

interface AuthorizationCodeMetadataStoreInterface
{
    /**
     * Persist metadata under the unique League authorization-code identifier.
     * Implementations must enforce uniqueness and expire records no later than $expiresAt.
     */
    public function store(string $authorizationCodeId, AuthorizationCodeMetadata $metadata): void;

    /**
     * Atomically retrieve and delete metadata. A successful call must return it at most once,
     * including when two token requests race to redeem the same authorization code.
     */
    public function consume(string $authorizationCodeId): ?AuthorizationCodeMetadata;
}
