# DarkSide OpenID Connect Server

Framework-independent PHP components for implementing an OpenID Connect Provider (OP), built on [League OAuth2 Server](https://oauth2.thephpleague.com/).

> **Project status: experimental.** The library implements a deliberately limited OpenID Connect Authorization Code profile. Its development has included automated tests and independent relying-party (RP) interoperability checks, including negative-flow and signing-key-rotation checks. It has **not** been formally certified by the OpenID Foundation and should not be treated as production-ready without a deployment-specific security and operational review.

The library is a provider component, not a complete identity server. Your application remains responsible for users, authentication, sessions, consent, client registration, persistence, routing, deployment and operational controls.

## Requirements

- PHP `^8.2` (CI is configured for PHP 8.2, 8.3, 8.4 and 8.5)
- OpenSSL and JSON PHP extensions
- Composer

## Installation

```bash
composer require darkside/openid-connect-server
```

## Quick example

Create the discovery document and JWKS payloads from the same issuer and RSA key pair used by your
provider. Load private-key material from a protected secret store; never commit it or place it under
the public web root.

```php
<?php

use DarkSide\OpenIdConnectServer\Discovery\DiscoveryDocumentGenerator;
use DarkSide\OpenIdConnectServer\Discovery\ProviderMetadata;
use DarkSide\OpenIdConnectServer\Jwks\JwksGenerator;
use DarkSide\OpenIdConnectServer\Key\SigningKey;
use DarkSide\OpenIdConnectServer\Token\IdTokenIssuer;

$issuer = 'https://identity.example.test';
$privateKeyPem = file_get_contents('/run/secrets/oidc-private.pem');
$publicKeyPem = file_get_contents('/run/secrets/oidc-public.pem');

if (!is_string($privateKeyPem) || !is_string($publicKeyPem)) {
    throw new RuntimeException('Unable to load the OIDC signing key pair.');
}

$signingKey = new SigningKey('oidc-rs256-2026-01', $privateKeyPem, $publicKeyPem);
$idTokenIssuer = new IdTokenIssuer($issuer, $signingKey, 300);

$metadata = new ProviderMetadata(
    issuer: $issuer,
    authorizationEndpoint: $issuer . '/authorize',
    tokenEndpoint: $issuer . '/token',
    jwksUri: $issuer . '/jwks',
    userinfoEndpoint: $issuer . '/userinfo',
    scopes: ['openid', 'profile', 'email'],
    claims: ['iss', 'sub', 'aud', 'exp', 'iat', 'auth_time', 'nonce', 'name', 'email', 'email_verified'],
);

$discoveryDocument = (new DiscoveryDocumentGenerator($metadata))->generate();
$jwks = (new JwksGenerator($signingKey))->generate();
```

Return `$discoveryDocument` and `$jwks` as JSON from the HTTPS routes named in the metadata. This
snippet only builds those protocol payloads and the ID Token issuer; it does not configure League,
authenticate users, persist authorization codes or mount HTTP routes. See the
[integration guide](docs/INTEGRATION-GUIDE.md) for complete host-application wiring.

## Supported protocol profile

The current implementation is intentionally narrow:

- OpenID Connect Authorization Code flow (`response_type=code`).
- PKCE is mandatory and only `S256` is accepted.
- An OIDC `nonce` is mandatory.
- RS256 ID Tokens.
- Discovery metadata and JWKS generation.
- UserInfo endpoint handler, using League's resource server to validate Bearer access tokens.
- Optional `max_age` handling, with re-authentication decisions owned by the host application.
- Opt-in `offline_access` with League refresh-token support, explicit `prompt=consent`, and single-use rotation/reuse hooks.
- Opt-in RP-Initiated and Back-Channel Logout protocol components, including Logout Token creation/validation and discovery metadata.
- Opt-in client-registration service with strict metadata checks and host-controlled access policy and storage.

The library does not implement or advertise implicit flow, password grant, Request Objects, token encryption or non-RS256 ID Token signing. New logout, offline-access and registration capabilities remain disabled unless explicitly configured.

## Main integration boundaries

| Component | Responsibility |
|---|---|
| `IdentityResolverInterface` | Maps League's authenticated resource-owner identifier to an application identity and client-/scope-appropriate claims. |
| `IdentityInterface` | Supplies a stable OIDC subject, permitted claims and authentication time. |
| League repositories | Persist clients, scopes, authorization codes and access tokens using application-owned storage. |
| `AuthorizationCodeMetadataStoreInterface` | Stores nonce/`max_age` metadata by League authorization-code ID and atomically consumes it once. |
| `OidcRequestContextProviderInterface` | Supplies request-local state shared by the OIDC grant, repository decorator and token response. |
| `SigningKey` / `SigningKeySet` | Configure the active RSA signing key and public-only retired verification keys. |
| `ProviderMetadata` | Explicitly describes the issuer and endpoints actually mounted by the host application. |

The library does not provide a database, framework integration, user model, login flow, consent UI, client administration or HTTP router. These remain application responsibilities.

## Integration guide

Start with **[docs/INTEGRATION-GUIDE.md](docs/INTEGRATION-GUIDE.md)** for the integration boundaries and wiring. See **[docs/OPTIONAL-PROTOCOL-MODULES.md](docs/OPTIONAL-PROTOCOL-MODULES.md)** for logout, offline access and registration extensions. Complete runnable host applications and the independent RP interoperability harness live in [darkside/openid-connect-server-examples](https://github.com/darkside666/openid-connect-server-examples).

Related references:

- [Security review and host-application responsibilities](docs/SECURITY-REVIEW.md)
- [Signing-key configuration and operational guidance](docs/SIGNING-KEY-CONFIGURATION.md)
- [Error handling, logging, caching and operations](docs/ERROR-HANDLING-AND-OPERATIONS.md)
- [Key-rotation interoperability procedure](https://github.com/darkside666/openid-connect-server-examples/blob/main/docs/PHASE-6D3-KEY-ROTATION.md)
- [Optional OpenID Foundation conformance testing notes](docs/OIDF-CONFORMANCE-TESTING.md)

## Development checks

Install development dependencies and run:

```bash
composer install
composer test
composer analyse
composer format:check
```

On Windows, set `OPENSSL_CONF` to the OpenSSL configuration shipped with your PHP installation before
these commands if required. In the shared development workspace, the `_set_openssl_conf.cmd` helper
is in the workspace root, one level above this repository. The interoperability workflow checks out
the examples repository; if that repository is private, configure an `EXAMPLES_REPOSITORY_TOKEN`
Actions secret with read access.

The reference provider and independent RP are **test-only** applications in [darkside/openid-connect-server-examples](https://github.com/darkside666/openid-connect-server-examples). The library CI selects the matching `main` or `develop` branch through Packagist for the provider dependency and runs live interoperability and security checks. The applications' own test suites are maintained with the examples.

Passing the project's automated checks and local independent-RP tests is useful verification evidence, but it is not a substitute for reviewing the security, persistence, deployment and operational properties of the application that integrates the library. It is not an OIDC conformance or certification claim.

## License

MIT
