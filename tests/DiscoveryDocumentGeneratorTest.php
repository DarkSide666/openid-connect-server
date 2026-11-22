<?php

declare(strict_types=1);

namespace DarkSide\OpenIdConnectServer\Tests;

use PHPUnit\Framework\TestCase;
use DarkSide\OpenIdConnectServer\Discovery\DiscoveryDocumentGenerator;
use DarkSide\OpenIdConnectServer\Discovery\ProviderMetadata;

final class DiscoveryDocumentGeneratorTest extends TestCase
{
    public function testAdvertisesOnlyConfiguredAndImplementedEndpoints(): void
    {
        $metadata = new ProviderMetadata(
            'https://identity.example.test',
            'https://identity.example.test/oauth/authorize',
            'https://identity.example.test/oauth/token',
            'https://identity.example.test/oauth/jwks',
        );

        $document = (new DiscoveryDocumentGenerator($metadata))->generate();

        self::assertSame('https://identity.example.test', $document['issuer']);
        self::assertSame(['code'], $document['response_types_supported']);
        self::assertSame(['S256'], $document['code_challenge_methods_supported']);
        self::assertSame(['authorization_code'], $document['grant_types_supported']);
        self::assertArrayNotHasKey('userinfo_endpoint', $document);
        self::assertArrayNotHasKey('registration_endpoint', $document);
    }

    public function testRejectsGrantTypesNotImplementedByThisLibraryProfile(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('supports only the authorization_code grant');

        new ProviderMetadata(
            'https://identity.example.test',
            'https://identity.example.test/oauth/authorize',
            'https://identity.example.test/oauth/token',
            'https://identity.example.test/oauth/jwks',
            grantTypes: ['authorization_code', 'refresh_token'],
        );
    }

    public function testRejectsUnsupportedResponseModesAndResponseTypes(): void
    {
        try {
            new ProviderMetadata(
                'https://identity.example.test',
                'https://identity.example.test/oauth/authorize',
                'https://identity.example.test/oauth/token',
                'https://identity.example.test/oauth/jwks',
                responseTypes: ['code', 'id_token'],
            );
            self::fail('Expected unsupported response type to be rejected.');
        } catch (\InvalidArgumentException $exception) {
            self::assertStringContainsString('response type', $exception->getMessage());
        }

        $this->expectException(\InvalidArgumentException::class);
        new ProviderMetadata(
            'https://identity.example.test',
            'https://identity.example.test/oauth/authorize',
            'https://identity.example.test/oauth/token',
            'https://identity.example.test/oauth/jwks',
            responseModes: ['query', 'form_post'],
        );
    }

    public function testAdvertisesOptInLogoutRefreshAndRegistrationMetadata(): void
    {
        $metadata = new ProviderMetadata(
            issuer: 'https://issuer.example.test',
            authorizationEndpoint: 'https://issuer.example.test/authorize',
            tokenEndpoint: 'https://issuer.example.test/token',
            jwksUri: 'https://issuer.example.test/jwks',
            scopes: ['openid', 'offline_access'],
            claims: ['iss', 'sub', 'aud', 'exp', 'iat', 'sid'],
            grantTypes: ['authorization_code', 'refresh_token'],
            offlineAccessSupported: true,
            endSessionEndpoint: 'https://issuer.example.test/logout',
            backchannelLogoutSupported: true,
            backchannelLogoutSessionSupported: true,
            registrationEndpoint: 'https://issuer.example.test/register',
        );
        $document = (new DiscoveryDocumentGenerator($metadata))->generate();
        self::assertSame('https://issuer.example.test/logout', $document['end_session_endpoint']);
        self::assertTrue($document['backchannel_logout_supported']);
        self::assertTrue($document['backchannel_logout_session_supported']);
        self::assertSame(['authorization_code', 'refresh_token'], $document['grant_types_supported']);
        self::assertSame('https://issuer.example.test/register', $document['registration_endpoint']);
    }

    public function testRejectsIssuerWithQueryCredentialsOrFragment(): void
    {
        foreach ([
            'https://user:pass@identity.example.test',
            'https://identity.example.test?tenant=one',
            'https://identity.example.test#fragment',
        ] as $issuer) {
            try {
                new ProviderMetadata(
                    $issuer,
                    'https://identity.example.test/oauth/authorize',
                    'https://identity.example.test/oauth/token',
                    'https://identity.example.test/oauth/jwks',
                );
                self::fail(sprintf('Expected invalid issuer "%s" to be rejected.', $issuer));
            } catch (\InvalidArgumentException) {
                self::assertTrue(true);
            }
        }
    }

    public function testRejectsEndpointUrlsWithCredentialsOrFragments(): void
    {
        foreach ([
            'https://user:pass@identity.example.test/oauth/token',
            'https://identity.example.test/oauth/token#fragment',
        ] as $tokenEndpoint) {
            try {
                new ProviderMetadata(
                    'https://identity.example.test',
                    'https://identity.example.test/oauth/authorize',
                    $tokenEndpoint,
                    'https://identity.example.test/oauth/jwks',
                );
                self::fail(sprintf('Expected invalid endpoint "%s" to be rejected.', $tokenEndpoint));
            } catch (\InvalidArgumentException) {
                self::assertTrue(true);
            }
        }
    }

    public function testAdvertisesUserInfoOnlyWhenConfigured(): void
    {
        $metadata = new ProviderMetadata(
            'https://identity.example.test',
            'https://identity.example.test/oauth/authorize',
            'https://identity.example.test/oauth/token',
            'https://identity.example.test/oauth/jwks',
            'https://identity.example.test/oauth/userinfo',
        );

        $document = (new DiscoveryDocumentGenerator($metadata))->generate();

        self::assertSame('https://identity.example.test/oauth/userinfo', $document['userinfo_endpoint']);
    }
}
