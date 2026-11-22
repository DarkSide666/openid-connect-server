<?php

declare(strict_types=1);

namespace DarkSide\OpenIdConnectServer\Registration;

final readonly class ClientRegistrationService
{
    public function __construct(
        private ClientRegistrationStoreInterface $store,
        private ClientRegistrationPolicyInterface $policy,
    ) {
    }

    /** @param array<string, mixed> $metadata */
    public function register(array $metadata, ?string $initialAccessToken = null): RegisteredClient
    {
        self::validateMetadata($metadata);
        if (!$this->policy->allows($metadata, $initialAccessToken)) {
            throw new \RuntimeException('Client registration is not permitted.');
        }
        $clientId = rtrim(strtr(base64_encode(random_bytes(24)), '+/', '-_'), '=');
        $provisioned = $this->policy->provision($metadata, $clientId);
        $provisioned['token_endpoint_auth_method'] ??= 'client_secret_basic';
        self::validateMetadata($provisioned);
        $authMethod = $provisioned['token_endpoint_auth_method'];
        $clientSecret = in_array($authMethod, ['client_secret_basic', 'client_secret_post'], true)
            ? rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=')
            : null;
        $client = new RegisteredClient($clientId, $provisioned, $clientSecret);
        $this->store->create($client);
        return $client;
    }

    /** @param array<string, mixed> $metadata */
    private static function validateMetadata(array $metadata): void
    {
        $allowed = [
            'redirect_uris', 'response_types', 'grant_types', 'application_type', 'client_name',
            'token_endpoint_auth_method', 'post_logout_redirect_uris', 'backchannel_logout_uri',
            'backchannel_logout_session_required',
        ];
        foreach ($metadata as $name => $value) {
            if (!in_array($name, $allowed, true)) {
                throw new \InvalidArgumentException(sprintf('Unsupported client metadata: %s.', (string) $name));
            }
        }
        $redirectUris = $metadata['redirect_uris'] ?? null;
        $nativeClient = ($metadata['application_type'] ?? null) === 'native';
        if (!is_array($redirectUris) || $redirectUris === [] || !array_is_list($redirectUris)) {
            throw new \InvalidArgumentException('redirect_uris must be a non-empty list.');
        }
        foreach (['redirect_uris', 'post_logout_redirect_uris'] as $field) {
            if (isset($metadata[$field])) {
                if (!is_array($metadata[$field]) || !array_is_list($metadata[$field])) {
                    throw new \InvalidArgumentException(sprintf('%s must be a list.', $field));
                }
                foreach ($metadata[$field] as $uri) {
                    $allowLoopbackHttp = $field === 'redirect_uris' && $nativeClient;
                    if (!is_string($uri) || !self::validUri($uri, $allowLoopbackHttp)) {
                        throw new \InvalidArgumentException(sprintf('%s contains an invalid URI.', $field));
                    }
                }
            }
        }
        foreach (['response_types' => ['code'], 'grant_types' => ['authorization_code']] as $field => $supported) {
            if (isset($metadata[$field]) && (!is_array($metadata[$field]) || $metadata[$field] !== $supported)) {
                throw new \InvalidArgumentException(sprintf('Unsupported %s.', $field));
            }
        }
        if (isset($metadata['application_type']) && !in_array($metadata['application_type'], ['web', 'native'], true)) {
            throw new \InvalidArgumentException('application_type must be web or native.');
        }
        if (isset($metadata['token_endpoint_auth_method'])
            && !in_array($metadata['token_endpoint_auth_method'], ['client_secret_basic', 'client_secret_post', 'private_key_jwt', 'none'], true)) {
            throw new \InvalidArgumentException('Unsupported token_endpoint_auth_method.');
        }
        if (isset($metadata['backchannel_logout_uri']) && (!is_string($metadata['backchannel_logout_uri']) || !self::validUri($metadata['backchannel_logout_uri']))) {
            throw new \InvalidArgumentException('Invalid backchannel_logout_uri.');
        }
        foreach (['backchannel_logout_session_required'] as $field) {
            if (isset($metadata[$field]) && !is_bool($metadata[$field])) {
                throw new \InvalidArgumentException(sprintf('%s must be boolean.', $field));
            }
        }
        foreach ($redirectUris as $uri) {
            if (!is_string($uri) || !self::validUri($uri, $nativeClient)) {
                throw new \InvalidArgumentException('redirect_uris contains an invalid URI.');
            }
        }
    }

    private static function validUri(string $uri, bool $allowLoopbackHttp = false): bool
    {
        $parts = parse_url($uri);
        if (filter_var($uri, FILTER_VALIDATE_URL) === false || !is_array($parts)
            || isset($parts['user']) || isset($parts['pass']) || isset($parts['fragment'])) {
            return false;
        }
        $scheme = strtolower((string) ($parts['scheme'] ?? ''));
        if ($scheme === 'https' && !empty($parts['host'])) {
            return true;
        }
        return $allowLoopbackHttp && $scheme === 'http'
            && in_array(strtolower((string) ($parts['host'] ?? '')), ['localhost', '127.0.0.1', '[::1]', '::1'], true);
    }
}
