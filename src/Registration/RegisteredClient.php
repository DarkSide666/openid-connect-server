<?php

declare(strict_types=1);

namespace DarkSide\OpenIdConnectServer\Registration;

final readonly class RegisteredClient
{
    /** @param array<string, mixed> $metadata */
    public function __construct(public string $clientId, public array $metadata, public ?string $clientSecret = null)
    {
        if ($clientId === '') {
            throw new \InvalidArgumentException('Client ID must not be empty.');
        }
    }
}
