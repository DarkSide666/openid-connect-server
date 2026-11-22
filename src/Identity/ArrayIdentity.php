<?php

declare(strict_types=1);

namespace DarkSide\OpenIdConnectServer\Identity;

use DateTimeImmutable;

final readonly class ArrayIdentity implements IdentityInterface
{
    /**
     * @param array<string, mixed> $claims
     */
    public function __construct(
        private string $subject,
        private array $claims = [],
        private ?DateTimeImmutable $authTime = null,
    ) {
        if ($subject === '') {
            throw new \InvalidArgumentException('The subject must not be empty.');
        }
    }

    public function subject(): string
    {
        return $this->subject;
    }

    /** @return array<string, mixed> */
    public function claims(): array
    {
        return $this->claims;
    }

    public function authTime(): ?DateTimeImmutable
    {
        return $this->authTime;
    }
}
