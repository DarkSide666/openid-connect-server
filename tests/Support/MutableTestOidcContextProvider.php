<?php

declare(strict_types=1);

namespace DarkSide\OpenIdConnectServer\Tests\Support;

use DarkSide\OpenIdConnectServer\Transaction\OidcRequestContext;
use DarkSide\OpenIdConnectServer\Transaction\OidcRequestContextProviderInterface;

/** Test-only provider that simulates a request-local context across sequential HTTP requests. */
final class MutableTestOidcContextProvider implements OidcRequestContextProviderInterface
{
    public function __construct(private OidcRequestContext $context)
    {
    }

    public function current(): OidcRequestContext
    {
        return $this->context;
    }

    public function beginRequest(): void
    {
        $this->context = new OidcRequestContext();
    }
}
