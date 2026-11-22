<?php

declare(strict_types=1);

namespace DarkSide\OpenIdConnectServer\Logout;

final readonly class RpInitiatedLogoutService
{
    public function __construct(private IdTokenHintValidator $hintValidator)
    {
    }

    /**
     * @param list<string> $registeredPostLogoutRedirectUris
     * @return array{client_id:?string,sub:?string,sid:?string,post_logout_redirect_uri:?string,state:?string}
     */
    public function validate(RpInitiatedLogoutRequest $request, array $registeredPostLogoutRedirectUris): array
    {
        $hint = $request->idTokenHint !== null ? $this->hintValidator->validate($request->idTokenHint) : null;
        if ($request->postLogoutRedirectUri !== null && $hint === null) {
            throw new \InvalidArgumentException('A valid id_token_hint is required for post-logout redirection.');
        }
        $clientId = $hint['client_id'] ?? $request->clientId;
        if ($clientId !== null && $request->clientId !== null && !hash_equals($clientId, $request->clientId)) {
            throw new \InvalidArgumentException('client_id does not match the ID Token hint audience.');
        }
        $redirect = null;
        if ($request->postLogoutRedirectUri !== null) {
            $redirect = $request->validateRedirect($hint['client_id'], $registeredPostLogoutRedirectUris);
        }
        return [
            'client_id' => $clientId,
            'sub' => $hint['sub'] ?? null,
            'sid' => $hint['sid'] ?? null,
            'post_logout_redirect_uri' => $redirect,
            'state' => $redirect !== null ? $request->state : null,
        ];
    }
}
