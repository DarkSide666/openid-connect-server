<?php

declare(strict_types=1);

namespace DarkSide\OpenIdConnectServer\League;

use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\ResponseTypes\BearerTokenResponse;
use SensitiveParameter;
use DarkSide\OpenIdConnectServer\Identity\IdentityResolverInterface;
use DarkSide\OpenIdConnectServer\Identity\SessionIdentityInterface;
use DarkSide\OpenIdConnectServer\Token\IdTokenIssuer;
use DarkSide\OpenIdConnectServer\Transaction\OidcRequestContextProviderInterface;

final class OidcBearerTokenResponse extends BearerTokenResponse
{
    public function __construct(
        private readonly IdTokenIssuer $idTokenIssuer,
        private readonly IdentityResolverInterface $identityResolver,
        private readonly OidcRequestContextProviderInterface $contextProvider,
    ) {
    }

    /**
     * @return array<string, string>
     */
    protected function getExtraParams(#[SensitiveParameter] AccessTokenEntityInterface $accessToken): array
    {
        if ($this->contextProvider->current()->isRefreshResponse()) {
            return [];
        }
        $grantedScopes = [];
        foreach ($accessToken->getScopes() as $scope) {
            $grantedScopes[] = $scope->getIdentifier();
        }

        if (!in_array('openid', $grantedScopes, true)) {
            return [];
        }

        $userIdentifier = $accessToken->getUserIdentifier();
        if ($userIdentifier === null) {
            throw new \LogicException('An OpenID Connect access token must identify a resource owner.');
        }

        $nonce = $this->contextProvider->current()->consumeRedeemedNonce();
        if ($nonce === null) {
            throw new \LogicException('The validated authorization code did not provide its bound OIDC nonce.');
        }

        $clientId = $accessToken->getClient()->getIdentifier();
        $maxAge = $this->contextProvider->current()->consumeRedeemedMaxAge();
        $identity = $this->identityResolver->resolve($userIdentifier, $clientId, $grantedScopes);
        $sessionId = $identity instanceof SessionIdentityInterface ? $identity->sessionId() : null;

        return [
            'id_token' => $this->idTokenIssuer->issue($clientId, $identity, $nonce, null, $grantedScopes, $maxAge, $sessionId),
        ];
    }
}
