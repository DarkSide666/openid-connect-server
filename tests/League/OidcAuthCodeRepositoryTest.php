<?php

declare(strict_types=1);

namespace DarkSide\OpenIdConnectServer\Tests\League;

use DateTimeImmutable;
use League\OAuth2\Server\Entities\AuthCodeEntityInterface;
use League\OAuth2\Server\Repositories\AuthCodeRepositoryInterface;
use PHPUnit\Framework\TestCase;
use DarkSide\OpenIdConnectServer\League\OidcAuthCodeRepository;
use DarkSide\OpenIdConnectServer\Tests\Support\InMemoryAuthorizationCodeMetadataStore;
use DarkSide\OpenIdConnectServer\Transaction\OidcRequestContext;
use DarkSide\OpenIdConnectServer\Transaction\OidcRequestContextProviderInterface;

final class OidcAuthCodeRepositoryTest extends TestCase
{
    public function testItBindsNonceToLeagueAuthorizationCodeIdentifier(): void
    {
        $inner = $this->createMock(AuthCodeRepositoryInterface::class);
        $authCode = $this->createMock(AuthCodeEntityInterface::class);
        $authCode->method('getIdentifier')->willReturn('league-code-123');
        $authCode->method('getExpiryDateTime')->willReturn(new DateTimeImmutable('+5 minutes'));

        $inner->expects(self::once())->method('persistNewAuthCode')->with($authCode);
        $inner->expects(self::once())->method('revokeAuthCode')->with('league-code-123');

        $context = new OidcRequestContext();
        $context->setPendingNonce('nonce-from-authorization-request');
        $provider = new TestContextProvider($context);
        $store = new InMemoryAuthorizationCodeMetadataStore();
        $repository = new OidcAuthCodeRepository($inner, $store, $provider);

        $repository->persistNewAuthCode($authCode);
        self::assertNull($context->pendingNonce());

        $repository->revokeAuthCode('league-code-123');
        self::assertSame('nonce-from-authorization-request', $context->consumeRedeemedNonce());
        self::assertNull($store->consume('league-code-123'));
    }



    public function testItBindsMaxAgeToTheAuthorizationCodeAndRedeemsItOnce(): void
    {
        $inner = $this->createMock(AuthCodeRepositoryInterface::class);
        $authCode = $this->createMock(AuthCodeEntityInterface::class);
        $authCode->method('getIdentifier')->willReturn('league-code-max-age');
        $authCode->method('getExpiryDateTime')->willReturn(new DateTimeImmutable('+5 minutes'));

        $context = new OidcRequestContext();
        $context->setPendingNonce('nonce-max-age', 120);
        $store = new InMemoryAuthorizationCodeMetadataStore();
        $repository = new OidcAuthCodeRepository($inner, $store, new TestContextProvider($context));

        $repository->persistNewAuthCode($authCode);
        $repository->revokeAuthCode('league-code-max-age');

        self::assertSame('nonce-max-age', $context->consumeRedeemedNonce());
        self::assertSame(120, $context->consumeRedeemedMaxAge());
        self::assertNull($store->consume('league-code-max-age'));
    }

    public function testItRevokesThePersistedCodeWhenNonceMetadataCannotBeStored(): void
    {
        $inner = $this->createMock(AuthCodeRepositoryInterface::class);
        $authCode = $this->createMock(AuthCodeEntityInterface::class);
        $authCode->method('getIdentifier')->willReturn('league-code-failed-store');
        $authCode->method('getExpiryDateTime')->willReturn(new DateTimeImmutable('+5 minutes'));
        $inner->expects(self::once())->method('persistNewAuthCode')->with($authCode);
        $inner->expects(self::once())->method('revokeAuthCode')->with('league-code-failed-store');

        $context = new OidcRequestContext();
        $context->setPendingNonce('nonce-123');
        $store = new class () implements \DarkSide\OpenIdConnectServer\Transaction\AuthorizationCodeMetadataStoreInterface {
            public function store(string $authorizationCodeId, \DarkSide\OpenIdConnectServer\Transaction\AuthorizationCodeMetadata $metadata): void
            {
                throw new \RuntimeException('storage unavailable');
            }

            public function consume(string $authorizationCodeId): ?\DarkSide\OpenIdConnectServer\Transaction\AuthorizationCodeMetadata
            {
                return null;
            }
        };
        $repository = new OidcAuthCodeRepository($inner, $store, new TestContextProvider($context));

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('storage unavailable');
        $repository->persistNewAuthCode($authCode);
    }

    public function testItFailsClosedWhenNonceMetadataIsMissingAtCodeRedemption(): void
    {
        $inner = $this->createMock(AuthCodeRepositoryInterface::class);
        $inner->expects(self::once())->method('revokeAuthCode')->with('unknown-code');
        $repository = new OidcAuthCodeRepository(
            $inner,
            new InMemoryAuthorizationCodeMetadataStore(),
            new TestContextProvider(new OidcRequestContext()),
        );

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('no valid, unconsumed OIDC nonce metadata');
        $repository->revokeAuthCode('unknown-code');
    }

    public function testItRefusesToPersistCodeWithoutNonce(): void
    {
        $inner = $this->createMock(AuthCodeRepositoryInterface::class);
        $inner->expects(self::never())->method('persistNewAuthCode');
        $authCode = $this->createMock(AuthCodeEntityInterface::class);

        $repository = new OidcAuthCodeRepository(
            $inner,
            new InMemoryAuthorizationCodeMetadataStore(),
            new TestContextProvider(new OidcRequestContext()),
        );

        $this->expectException(\LogicException::class);
        $repository->persistNewAuthCode($authCode);
    }
}

final readonly class TestContextProvider implements OidcRequestContextProviderInterface
{
    public function __construct(private OidcRequestContext $context)
    {
    }

    public function current(): OidcRequestContext
    {
        return $this->context;
    }
}
