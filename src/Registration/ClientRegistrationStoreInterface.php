<?php

declare(strict_types=1);

namespace DarkSide\OpenIdConnectServer\Registration;

interface ClientRegistrationStoreInterface
{
    public function create(RegisteredClient $client): void;
}
