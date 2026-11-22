<?php

declare(strict_types=1);

namespace DarkSide\OpenIdConnectServer\Logout;

final readonly class RpInitiatedLogoutRequest
{
    public function __construct(
        public ?string $idTokenHint,
        public ?string $clientId,
        public ?string $postLogoutRedirectUri,
        public ?string $state,
    ) {
        foreach (['id_token_hint' => $idTokenHint, 'client_id' => $clientId, 'post_logout_redirect_uri' => $postLogoutRedirectUri, 'state' => $state] as $name => $value) {
            if ($value !== null && ($value === '' || strlen($value) > 4096)) {
                throw new \InvalidArgumentException(sprintf('Invalid %s parameter.', $name));
            }
        }
    }

    /** @param array<string, mixed> $query */
    public static function fromQuery(array $query): self
    {
        foreach (['id_token_hint', 'client_id', 'post_logout_redirect_uri', 'state'] as $name) {
            if (isset($query[$name]) && !is_string($query[$name])) {
                throw new \InvalidArgumentException(sprintf('The %s parameter must be a string.', $name));
            }
        }
        return new self($query['id_token_hint'] ?? null, $query['client_id'] ?? null, $query['post_logout_redirect_uri'] ?? null, $query['state'] ?? null);
    }

    /** Exact match; callers must verify the hint and bind its audience to this client before redirecting. */
    /** @param list<string> $registeredUris */
    public function validateRedirect(string $clientId, array $registeredUris): ?string
    {
        if ($this->postLogoutRedirectUri === null) {
            return null;
        }
        if (($this->clientId !== null && !hash_equals($clientId, $this->clientId)) || !in_array($this->postLogoutRedirectUri, $registeredUris, true)) {
            throw new \InvalidArgumentException('The post-logout redirect URI is not registered for this client.');
        }
        return $this->postLogoutRedirectUri;
    }
}
