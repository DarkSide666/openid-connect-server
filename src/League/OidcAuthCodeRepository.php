<?php

declare(strict_types=1);

namespace DarkSide\OpenIdConnectServer\League;

use League\OAuth2\Server\Entities\AuthCodeEntityInterface;
use League\OAuth2\Server\Repositories\AuthCodeRepositoryInterface;
use DarkSide\OpenIdConnectServer\Transaction\AuthorizationCodeMetadata;
use DarkSide\OpenIdConnectServer\Transaction\AuthorizationCodeMetadataStoreInterface;
use DarkSide\OpenIdConnectServer\Transaction\OidcRequestContextProviderInterface;
use Throwable;

/**
 * Decorates the application's League repository to bind OIDC nonce and max_age metadata to
 * League's opaque, single-use authorization-code identifier.
 */
final readonly class OidcAuthCodeRepository implements AuthCodeRepositoryInterface
{
    public function __construct(
        private AuthCodeRepositoryInterface $inner,
        private AuthorizationCodeMetadataStoreInterface $metadataStore,
        private OidcRequestContextProviderInterface $contextProvider,
    ) {
    }

    public function getNewAuthCode(): AuthCodeEntityInterface
    {
        return $this->inner->getNewAuthCode();
    }

    public function persistNewAuthCode(AuthCodeEntityInterface $authCodeEntity): void
    {
        $context = $this->contextProvider->current();
        if ($context->pendingNonce() === null) {
            throw new \LogicException('Refusing to persist an OIDC authorization code without its request nonce.');
        }

        $this->inner->persistNewAuthCode($authCodeEntity);
        $nonce = $context->consumePendingNonce();
        $maxAge = $context->consumePendingMaxAge();

        if ($nonce === null) {
            $this->inner->revokeAuthCode($authCodeEntity->getIdentifier());
            throw new \LogicException('The OIDC nonce disappeared while persisting the authorization code.');
        }

        try {
            $this->metadataStore->store(
                $authCodeEntity->getIdentifier(),
                new AuthorizationCodeMetadata($nonce, $authCodeEntity->getExpiryDateTime(), $maxAge, $context->consumePendingSessionId()),
            );
        } catch (Throwable $exception) {
            // Never leave a usable OAuth authorization code without its OIDC binding.
            $this->inner->revokeAuthCode($authCodeEntity->getIdentifier());
            throw $exception;
        }
    }

    public function revokeAuthCode(string $codeId): void
    {
        $this->inner->revokeAuthCode($codeId);

        $metadata = $this->metadataStore->consume($codeId);
        if ($metadata === null || $metadata->expiresAt <= new \DateTimeImmutable()) {
            throw new \LogicException('The authorization code has no valid, unconsumed OIDC nonce metadata.');
        }

        $this->contextProvider->current()->setRedeemedNonce($metadata->nonce, $metadata->maxAge, $metadata->sessionId);
    }

    public function isAuthCodeRevoked(string $codeId): bool
    {
        return $this->inner->isAuthCodeRevoked($codeId);
    }
}
