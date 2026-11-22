<?php

declare(strict_types=1);

namespace DarkSide\OpenIdConnectServer\Identity;

interface IdentityResolverInterface
{
    /**
     * Resolve the application user into the OIDC subject and claims for this client.
     * Implementations must filter application-defined claims according to the granted scopes and
     * client disclosure policy. The Provider independently filters standard OIDC claims by their
     * corresponding standard scopes as defense in depth.
     *
     * @param list<string> $grantedScopes
     */
    public function resolve(string $userIdentifier, string $clientId, array $grantedScopes): IdentityInterface;
}
