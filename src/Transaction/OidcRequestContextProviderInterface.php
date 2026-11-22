<?php

declare(strict_types=1);

namespace DarkSide\OpenIdConnectServer\Transaction;

interface OidcRequestContextProviderInterface
{
    /**
     * Return the context belonging to the currently executing HTTP request.
     * Implementations used by long-running/concurrent workers must be request- or fiber-local.
     */
    public function current(): OidcRequestContext;
}
