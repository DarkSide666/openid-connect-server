<?php

declare(strict_types=1);

namespace DarkSide\OpenIdConnectServer\Identity;

interface SessionIdentityInterface extends IdentityInterface
{
    /** Opaque issuer-scoped session identifier for OIDC sid claims. */
    public function sessionId(): string;
}
