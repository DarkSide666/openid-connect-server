<?php

declare(strict_types=1);

namespace DarkSide\OpenIdConnectServer\Tests\Registration;

use PHPUnit\Framework\TestCase;
use DarkSide\OpenIdConnectServer\Registration\ClientRegistrationPolicyInterface;
use DarkSide\OpenIdConnectServer\Registration\ClientRegistrationService;
use DarkSide\OpenIdConnectServer\Registration\ClientRegistrationStoreInterface;
use DarkSide\OpenIdConnectServer\Registration\RegisteredClient;

final class ClientRegistrationServiceTest extends TestCase
{
    public function testCreatesValidatedClientThroughHostPolicyAndStore(): void
    {
        $store = new class () implements ClientRegistrationStoreInterface {
            public ?RegisteredClient $created = null;
            public function create(RegisteredClient $client): void
            {
                $this->created = $client;
            }
        };
        $policy = new class () implements ClientRegistrationPolicyInterface {
            public function allows(array $metadata, ?string $initialAccessToken): bool
            {
                return $initialAccessToken === 'trusted';
            }
            public function provision(array $metadata, string $clientId): array
            {
                return $metadata;
            }
        };
        $service = new ClientRegistrationService($store, $policy);
        $client = $service->register(['redirect_uris' => ['https://rp.example.test/callback']], 'trusted');
        self::assertSame($client, $store->created);
        self::assertSame(['https://rp.example.test/callback'], $client->metadata['redirect_uris']);
        self::assertNotSame('', $client->clientId);
        self::assertNotNull($client->clientSecret);
    }

    public function testRejectsUnsafeRedirectUri(): void
    {
        $store = $this->createMock(ClientRegistrationStoreInterface::class);
        $policy = $this->createMock(ClientRegistrationPolicyInterface::class);
        $service = new ClientRegistrationService($store, $policy);
        $this->expectException(\InvalidArgumentException::class);
        $service->register(['redirect_uris' => ['http://rp.example.test/callback']]);
    }

    public function testAllowsHttpLoopbackForNativeClientRedirects(): void
    {
        $store = new class () implements ClientRegistrationStoreInterface {
            public function create(RegisteredClient $client): void
            {
            }
        };
        $policy = new class () implements ClientRegistrationPolicyInterface {
            public function allows(array $metadata, ?string $initialAccessToken): bool
            {
                return true;
            }

            public function provision(array $metadata, string $clientId): array
            {
                return $metadata + ['token_endpoint_auth_method' => 'none'];
            }
        };
        $client = (new ClientRegistrationService($store, $policy))->register([
            'application_type' => 'native',
            'redirect_uris' => ['http://127.0.0.1:49152/callback'],
        ]);
        self::assertNull($client->clientSecret);
    }
}
