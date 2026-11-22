<?php

declare(strict_types=1);

namespace DarkSide\OpenIdConnectServer\Discovery;

final readonly class ProviderMetadata
{
    /**
     * @param array<mixed> $scopes
     * @param array<mixed> $claims
     * @param array<mixed> $tokenEndpointAuthMethods
     * @param array<mixed> $grantTypes
     * @param array<mixed> $responseTypes
     * @param array<mixed> $responseModes
     * @param array<mixed> $codeChallengeMethods
     */
    public function __construct(
        public string $issuer,
        public string $authorizationEndpoint,
        public string $tokenEndpoint,
        public string $jwksUri,
        public ?string $userinfoEndpoint = null,
        public array $scopes = ['openid'],
        public array $claims = ['iss', 'sub', 'aud', 'exp', 'iat', 'auth_time', 'nonce'],
        public array $tokenEndpointAuthMethods = ['client_secret_basic'],
        public array $grantTypes = ['authorization_code'],
        public array $responseTypes = ['code'],
        public array $responseModes = ['query'],
        public array $codeChallengeMethods = ['S256'],
        public ?string $endSessionEndpoint = null,
        public bool $backchannelLogoutSupported = false,
        public bool $backchannelLogoutSessionSupported = false,
        public bool $offlineAccessSupported = false,
        public ?string $registrationEndpoint = null,
    ) {
        foreach (['issuer' => $issuer, 'authorization_endpoint' => $authorizationEndpoint, 'token_endpoint' => $tokenEndpoint, 'jwks_uri' => $jwksUri] as $name => $url) {
            self::assertHttpsUrl($name, $url, $name === 'issuer');
        }
        if ($userinfoEndpoint !== null) {
            self::assertHttpsUrl('userinfo_endpoint', $userinfoEndpoint);
        }
        foreach (['end_session_endpoint' => $endSessionEndpoint, 'registration_endpoint' => $registrationEndpoint] as $name => $url) {
            if ($url !== null) {
                self::assertHttpsUrl($name, $url);
            }
        }

        self::assertNonEmptyStringList('scopes', $scopes);
        self::assertNonEmptyStringList('claims', $claims);
        self::assertNonEmptyStringList('token endpoint authentication methods', $tokenEndpointAuthMethods);
        self::assertNonEmptyStringList('grant types', $grantTypes);
        self::assertNonEmptyStringList('response types', $responseTypes);
        self::assertNonEmptyStringList('response modes', $responseModes);
        self::assertNonEmptyStringList('PKCE challenge methods', $codeChallengeMethods);

        if (!in_array('openid', $scopes, true)) {
            throw new \InvalidArgumentException('An OpenID Provider must advertise the openid scope.');
        }
        $supportedGrantTypes = $offlineAccessSupported ? ['authorization_code', 'refresh_token'] : ['authorization_code'];
        if ($responseTypes !== ['code']) {
            throw new \InvalidArgumentException('This library profile supports only the code response type.');
        }
        if ($grantTypes !== $supportedGrantTypes) {
            throw new \InvalidArgumentException('This library profile supports only the authorization_code grant, with refresh_token enabled only for offline access.');
        }
        if ($responseModes !== ['query']) {
            throw new \InvalidArgumentException('This library profile supports only the query response mode.');
        }
        if ($codeChallengeMethods !== ['S256']) {
            throw new \InvalidArgumentException('This library profile supports only PKCE S256.');
        }
        if ($offlineAccessSupported !== in_array('offline_access', $scopes, true)) {
            throw new \InvalidArgumentException('Advertise offline_access only when offline access support is enabled.');
        }
        if ($backchannelLogoutSessionSupported && !$backchannelLogoutSupported) {
            throw new \InvalidArgumentException('Back-channel session logout requires back-channel logout support.');
        }
        if ($backchannelLogoutSessionSupported && !in_array('sid', $claims, true)) {
            throw new \InvalidArgumentException('Session logout support requires sid in claims_supported.');
        }

        foreach (['iss', 'sub', 'aud', 'exp', 'iat'] as $requiredClaim) {
            if (!in_array($requiredClaim, $claims, true)) {
                throw new \InvalidArgumentException(sprintf('The claims_supported list must include the required "%s" claim.', $requiredClaim));
            }
        }
    }

    private static function assertHttpsUrl(string $name, string $url, bool $issuer = false): void
    {
        $parts = parse_url($url);
        if (
            !filter_var($url, FILTER_VALIDATE_URL)
            || !is_array($parts)
            || strtolower((string) ($parts['scheme'] ?? '')) !== 'https'
            || empty($parts['host'])
            || isset($parts['user'])
            || isset($parts['pass'])
            || isset($parts['fragment'])
            || ($issuer && isset($parts['query']))
        ) {
            $detail = $issuer ? 'an absolute HTTPS URL without credentials, query or fragment' : 'an absolute HTTPS URL without credentials or fragment';
            throw new \InvalidArgumentException(sprintf('The %s must be %s.', $name, $detail));
        }
    }

    /** @param array<mixed> $values */
    private static function assertNonEmptyStringList(string $name, array $values): void
    {
        if ($values === [] || !array_is_list($values)) {
            throw new \InvalidArgumentException(sprintf('The %s list must be a non-empty list.', $name));
        }
        foreach ($values as $value) {
            if (!is_string($value) || $value === '') {
                throw new \InvalidArgumentException(sprintf('The %s list must contain non-empty strings only.', $name));
            }
        }
    }
}
