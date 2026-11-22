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
            $response = parent::respondToAccessTokenRequest($request, $responseType, $accessTokenTTL);
            if ($responseType instanceof OidcBearerTokenResponse) {
                // AuthorizationServer serializes the response after this method returns, so a
                // request-context flag cleared in finally would be too early.
                $responseType->markRefreshResponse();
            }
            return $response;
        } catch (RefreshTokenReplayException $exception) {
            $this->rotationRepository->revokeFamilyForReusedToken($exception->refreshTokenId);
            throw OAuthServerException::invalidRefreshToken('Refresh token replay detected.', $exception);
        } catch (OAuthServerException $exception) {
            throw $exception;
        } finally {
            if ($rotationStarted) {
                $this->rotationRepository->endRotation();
            }
            $this->contextProvider->current()->setRefreshResponse(false);
        }
    }

    /** @return array<string, mixed> */
    protected function validateOldRefreshToken(ServerRequestInterface $request, string $clientId): array
    {
        $encrypted = $this->getRequestParameter('refresh_token', $request)
            ?? throw OAuthServerException::invalidRequest('refresh_token');
        try {
            $payload = json_decode($this->decrypt($encrypted), true, 512, JSON_THROW_ON_ERROR);
        } catch (\Throwable $exception) {
            throw OAuthServerException::invalidRefreshToken('Cannot decrypt the refresh token', $exception);
        }
        if (!is_array($payload)
            || !is_string($payload['refresh_token_id'] ?? null)
            || !is_string($payload['client_id'] ?? null)
            || !is_numeric($payload['expire_time'] ?? null)
            || !is_array($payload['scopes'] ?? null)) {
            throw OAuthServerException::invalidRefreshToken('Malformed refresh token.');
        }
        if (!hash_equals($clientId, $payload['client_id'])) {
            throw OAuthServerException::invalidRefreshToken('Token is not linked to client.');
        }
        if ((int) $payload['expire_time'] < time()) {
            throw OAuthServerException::invalidRefreshToken('Token has expired.');
        }
        $consumption = $this->rotationRepository->consumeRefreshToken($payload['refresh_token_id']);
        if ($consumption === RefreshTokenConsumptionResult::REPLAYED) {
            throw new RefreshTokenReplayException($payload['refresh_token_id']);
        }
        if ($consumption !== RefreshTokenConsumptionResult::CONSUMED) {
            throw OAuthServerException::invalidRefreshToken('Refresh token is invalid, expired, or revoked.');
        }
        return $payload;
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
