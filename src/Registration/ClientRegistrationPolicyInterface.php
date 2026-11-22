<?php

declare(strict_types=1);

namespace DarkSide\OpenIdConnectServer\Registration;

interface ClientRegistrationPolicyInterface
{
    /** @param array<string, mixed> $metadata Return false to reject the request. */
    public function allows(array $metadata, ?string $initialAccessToken): bool;

    /**
     * @param array<string, mixed> $metadata
     * @return array<string, mixed>
     */
    public function provision(array $metadata, string $clientId): array;
}
