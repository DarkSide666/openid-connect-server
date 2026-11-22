<?php

declare(strict_types=1);

namespace DarkSide\OpenIdConnectServer\Logout;

interface LogoutClientStoreInterface
{
    /** @return iterable<array{client_id:string,logout_uri:string,session_required:bool}> */
    public function recipients(string $subject, ?string $sessionId): iterable;
}
