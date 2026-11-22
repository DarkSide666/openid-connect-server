<?php

declare(strict_types=1);

namespace DarkSide\OpenIdConnectServer\League;

use DateInterval;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Grant\RefreshTokenGrant;
use League\OAuth2\Server\ResponseTypes\ResponseTypeInterface;
use Psr\Http\Message\ServerRequestInterface;
use DarkSide\OpenIdConnectServer\Transaction\OidcRequestContextProviderInterface;

final class OidcRefreshTokenGrant extends RefreshTokenGrant
{
    public function __construct(
        private readonly RotatingRefreshTokenRepositoryInterface $rotationRepository,
        private readonly OidcRequestContextProviderInterface $contextProvider,
        DateInterval $refreshTokenTtl,
    ) {
        parent::__construct($rotationRepository);
        $this->setRefreshTokenTTL($refreshTokenTtl);
        $this->revokeRefreshTokens(true);
    }

    public function respondToAccessTokenRequest(
        ServerRequestInterface $request,
        ResponseTypeInterface $responseType,
        DateInterval $accessTokenTTL,
    ): ResponseTypeInterface {
        // Authenticate before touching token-family state; otherwise an attacker
        // could force family revocation merely by presenting a known spent token.
        $this->validateClient($request);
        $this->contextProvider->current()->setRefreshResponse(true);
        $tokenId = $this->presentedRefreshTokenId($request);
        $rotationStarted = false;
        try {
            if ($tokenId !== null) {
                $this->rotationRepository->beginRotation($tokenId);
                $rotationStarted = true;
            }
            return parent::respondToAccessTokenRequest($request, $responseType, $accessTokenTTL);
        } catch (OAuthServerException $exception) {
            if ($tokenId !== null && $this->rotationRepository->isRefreshTokenRevoked($tokenId)) {
                $this->rotationRepository->revokeFamilyForReusedToken($tokenId);
            }
            throw $exception;
        } finally {
            if ($rotationStarted) {
                $this->rotationRepository->endRotation();
            }
            $this->contextProvider->current()->setRefreshResponse(false);
        }
    }

    private function presentedRefreshTokenId(ServerRequestInterface $request): ?string
    {
        $presented = $this->getRequestParameter('refresh_token', $request);
        if ($presented === null) {
            return null;
        }
        try {
            $payload = json_decode($this->decrypt($presented), true, 512, JSON_THROW_ON_ERROR);
        } catch (\Throwable) {
            return null;
        }
        $tokenId = is_array($payload) ? ($payload['refresh_token_id'] ?? null) : null;
        return is_string($tokenId) && $tokenId !== '' ? $tokenId : null;
    }
}
