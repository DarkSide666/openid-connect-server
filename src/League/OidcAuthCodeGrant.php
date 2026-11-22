<?php

declare(strict_types=1);

namespace DarkSide\OpenIdConnectServer\League;

use DateInterval;
use League\OAuth2\Server\Grant\AuthCodeGrant;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\RefreshTokenEntityInterface;
use League\OAuth2\Server\Repositories\AuthCodeRepositoryInterface;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;
use League\OAuth2\Server\RequestTypes\AuthorizationRequestInterface;
use League\OAuth2\Server\ResponseTypes\ResponseTypeInterface;
use Psr\Http\Message\ServerRequestInterface;
use DarkSide\OpenIdConnectServer\Transaction\OidcRequestContextProviderInterface;
use DarkSide\OpenIdConnectServer\Transaction\OidcSessionIdProviderInterface;

final class OidcAuthCodeGrant extends AuthCodeGrant
{
    public function __construct(
        AuthCodeRepositoryInterface $authCodeRepository,
        RefreshTokenRepositoryInterface $refreshTokenRepository,
        DateInterval $authorizationCodeTtl,
        private readonly OidcRequestContextProviderInterface $contextProvider,
        private readonly bool $offlineAccessEnabled = false,
        private readonly ?OidcSessionIdProviderInterface $sessionIdProvider = null,
    ) {
        parent::__construct($authCodeRepository, $refreshTokenRepository, $authorizationCodeTtl);
    }

    public function validateAuthorizationRequest(ServerRequestInterface $request): AuthorizationRequestInterface
    {
        $authorizationRequest = parent::validateAuthorizationRequest($request);

        if (!$authorizationRequest instanceof OidcAuthorizationRequest) {
            throw new \LogicException('League did not create the expected OIDC authorization request.');
        }

        $hasOpenIdScope = false;
        foreach ($authorizationRequest->getScopes() as $scope) {
            if ($scope->getIdentifier() === 'openid') {
                $hasOpenIdScope = true;
            }
            if ($scope->getIdentifier() === 'offline_access' && !$this->offlineAccessEnabled) {
                $redirectUri = $authorizationRequest->getRedirectUri()
                    ?? $this->getClientRedirectUri($authorizationRequest->getClient());
                throw \League\OAuth2\Server\Exception\OAuthServerException::invalidScope('offline_access', $redirectUri);
            }
        }

        if (!$hasOpenIdScope) {
            $redirectUri = $authorizationRequest->getRedirectUri()
                ?? $this->getClientRedirectUri($authorizationRequest->getClient());
            throw \League\OAuth2\Server\Exception\OAuthServerException::invalidScope('openid', $redirectUri);
        }

        if ($authorizationRequest->getCodeChallenge() === null || $authorizationRequest->getCodeChallengeMethod() !== 'S256') {
            throw \League\OAuth2\Server\Exception\OAuthServerException::invalidRequest(
                'code_challenge',
                'OpenID Connect Authorization Code requests require PKCE with S256.',
            );
        }

        $query = $request->getQueryParams();
        $nonce = $query['nonce'] ?? null;
        if (!is_string($nonce) || $nonce === '' || strlen($nonce) > 256) {
            throw \League\OAuth2\Server\Exception\OAuthServerException::invalidRequest(
                'nonce',
                'A non-empty nonce of at most 256 bytes is required.',
            );
        }

        $authorizationRequest->setNonce($nonce);
        $scopes = array_map(static fn ($scope): string => $scope->getIdentifier(), $authorizationRequest->getScopes());
        if ($this->offlineAccessEnabled && in_array('offline_access', $scopes, true)) {
            $prompt = $query['prompt'] ?? '';
            $prompts = is_string($prompt) ? preg_split('/\s+/', trim($prompt), -1, PREG_SPLIT_NO_EMPTY) : false;
            if (!is_array($prompts) || !in_array('consent', $prompts, true) || in_array('none', $prompts, true)) {
                throw \League\OAuth2\Server\Exception\OAuthServerException::invalidRequest(
                    'prompt',
                    'offline_access requires explicit consent (prompt=consent).',
                );
            }
        }

        $maxAge = $query['max_age'] ?? null;
        if ($maxAge !== null) {
            if (is_string($maxAge) && preg_match('/^[0-9]+$/D', $maxAge) === 1) {
                $normalizedMaxAge = ltrim($maxAge, '0');
                $maxAge = filter_var($normalizedMaxAge === '' ? '0' : $normalizedMaxAge, FILTER_VALIDATE_INT, ['options' => ['min_range' => 0]]);
            } elseif (!is_int($maxAge) || $maxAge < 0) {
                $maxAge = false;
            }

            if (!is_int($maxAge)) {
                throw \League\OAuth2\Server\Exception\OAuthServerException::invalidRequest(
                    'max_age',
                    'The max_age parameter must be a non-negative integer.',
                );
            }
        }
        $authorizationRequest->setMaxAge($maxAge);

        return $authorizationRequest;
    }

    public function completeAuthorizationRequest(AuthorizationRequestInterface $authorizationRequest): ResponseTypeInterface
    {
        if (!$authorizationRequest instanceof OidcAuthorizationRequest) {
            throw new \InvalidArgumentException('Expected an OIDC authorization request.');
        }

        $context = $this->contextProvider->current();
        $context->setPendingNonce($authorizationRequest->nonce(), $authorizationRequest->maxAge());

        try {
            $context->setPendingSessionId($this->sessionIdProvider?->sessionId($authorizationRequest));
            return parent::completeAuthorizationRequest($authorizationRequest);
        } finally {
            // The repository decorator consumes this while League persists the code.
            // Clear it as a safety net for denied or exceptional authorization requests.
            $context->clearPendingNonce();
        }
    }

    /** Refresh tokens are opt-in and only issued for explicitly consented offline access. */
    protected function issueRefreshToken(AccessTokenEntityInterface $accessToken): ?RefreshTokenEntityInterface
    {
        if (!$this->offlineAccessEnabled) {
            return null;
        }
        foreach ($accessToken->getScopes() as $scope) {
            if ($scope->getIdentifier() === 'offline_access') {
                return parent::issueRefreshToken($accessToken);
            }
        }
        return null;
    }

    protected function createAuthorizationRequest(): AuthorizationRequestInterface
    {
        return new OidcAuthorizationRequest();
    }
}
