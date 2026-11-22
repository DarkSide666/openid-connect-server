<?php

declare(strict_types=1);

namespace DarkSide\OpenIdConnectServer\Transaction;

/**
 * Simple provider for applications that can construct the OIDC service graph per request.
 * Do not register this instance as a process-wide singleton.
 */
final readonly class RequestScopedOidcContextProvider implements OidcRequestContextProviderInterface
{
    public function __construct(private OidcRequestContext $context)
    {
    }

    public function current(): OidcRequestContext
    {
        return $this->context;
    }
}
