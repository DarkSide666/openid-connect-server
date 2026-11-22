<?php

declare(strict_types=1);

namespace DarkSide\OpenIdConnectServer\Identity;

use DateTimeImmutable;

interface IdentityInterface
{
    /**
     * Stable, issuer-scoped subject identifier. Must not be an email address
     * or a sequential database identifier.
     */
    public function subject(): string;

    /**
     * Additional OIDC claims permitted for this identity and authorization.
     *
     * Reserved protocol claims (iss, sub, aud, exp, iat, nonce, azp, etc.)
     * are controlled by the Provider and must not be returned here.
     *
     * @return array<string, mixed>
     */
    public function claims(): array;

    /**
     * Time at which the end-user authentication occurred. Required when the
     * authorization request included max_age.
     */
    public function authTime(): ?DateTimeImmutable;
}
