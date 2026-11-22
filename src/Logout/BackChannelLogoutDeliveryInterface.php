<?php

declare(strict_types=1);

namespace DarkSide\OpenIdConnectServer\Logout;

interface BackChannelLogoutDeliveryInterface
{
    /** Send a form-encoded logout_token to the registered HTTPS endpoint. */
    public function deliver(string $clientId, string $logoutUri, string $logoutToken): void;
}
