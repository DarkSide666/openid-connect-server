<?php

declare(strict_types=1);

namespace DarkSide\OpenIdConnectServer\Transaction;

use League\OAuth2\Server\RequestTypes\AuthorizationRequestInterface;

interface OidcSessionIdProviderInterface
{
    /** Return the current authenticated OP session ID after the host has approved the request. */
    public function sessionId(AuthorizationRequestInterface $authorizationRequest): ?string;
}
