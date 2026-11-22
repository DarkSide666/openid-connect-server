<?php

declare(strict_types=1);

namespace DarkSide\OpenIdConnectServer\Tests\Transaction;

use PHPUnit\Framework\TestCase;
use DarkSide\OpenIdConnectServer\Transaction\OidcRequestContext;

final class OidcRequestContextTest extends TestCase
{
    public function testNonceMovesFromAuthorizationToTokenResponseExactlyOnce(): void
    {
        $context = new OidcRequestContext();
        $context->setPendingNonce('nonce-value');

        self::assertSame('nonce-value', $context->consumePendingNonce());
        self::assertNull($context->consumePendingNonce());

        $context->setRedeemedNonce('nonce-value');
        self::assertSame('nonce-value', $context->consumeRedeemedNonce());
        self::assertNull($context->consumeRedeemedNonce());
    }

    public function testItRejectsReusingContextAcrossTransactions(): void
    {
        $context = new OidcRequestContext();
        $context->setPendingNonce('first');

        $this->expectException(\LogicException::class);
        $context->setPendingNonce('second');
    }

    public function testSessionIdMovesWithTheAuthorizationCodeMetadataExactlyOnce(): void
    {
        $context = new OidcRequestContext();
        $context->setPendingSessionId('session-123');

        self::assertSame('session-123', $context->consumePendingSessionId());
        self::assertNull($context->consumePendingSessionId());

        $context->setRedeemedNonce('nonce-value', null, 'session-123');
        self::assertSame('session-123', $context->consumeRedeemedSessionId());
        self::assertNull($context->consumeRedeemedSessionId());
    }
}
