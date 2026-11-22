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

## Supported protocol profile

The current implementation is intentionally narrow:

- OpenID Connect Authorization Code flow (`response_type=code`).
- PKCE is mandatory and only `S256` is accepted.
- An OIDC `nonce` is mandatory.
- RS256 ID Tokens.
- Discovery metadata and JWKS generation.
- UserInfo endpoint handler, using League's resource server to validate Bearer access tokens.
- Optional `max_age` handling, with re-authentication decisions owned by the host application.
- No refresh-token issuance by this OIDC grant adapter.

The library does not implement or advertise implicit flow, password grant, refresh-token grant, Dynamic Client Registration, logout, Request Objects, token encryption or non-RS256 ID Token signing.

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

Start with **[docs/INTEGRATION-GUIDE.md](docs/INTEGRATION-GUIDE.md)** for the integration boundaries and wiring. Complete runnable host applications and the independent RP interoperability harness live in [darkside/openid-connect-server-examples](https://github.com/darkside666/openid-connect-server-examples).

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

On Windows, call `set OPENSSL_CONF=path_to_php\extras\ssl\openssl.cnf` before these commands when the local OpenSSL installation
requires `OPENSSL_CONF`. The interoperability workflow checks out the examples repository; if it is
private, configure an `EXAMPLES_REPOSITORY_TOKEN` Actions secret with read access.

The reference provider and independent RP are **test-only** applications in [darkside/openid-connect-server-examples](https://github.com/darkside666/openid-connect-server-examples). The library CI checks them against the current library source; their application-specific test suites are maintained with the examples.

Passing the project's automated checks and local independent-RP tests is useful verification evidence, but it is not a substitute for reviewing the security, persistence, deployment and operational properties of the application that integrates the library. It is not an OIDC conformance or certification claim.

## License

MIT
