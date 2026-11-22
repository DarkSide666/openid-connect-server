# Security review and deployment checklist

## Scope

This document records the security boundaries and review checks for the `darkside/openid-connect-server`
component library. It is not a penetration-test report, security audit, certification statement,
or guarantee that an integrating application is secure.

The library provides OIDC components on top of League OAuth2 Server. The host application still
owns HTTP routing, client registration and secrets, user authentication, interactive login,
consent/approval, durable persistence, deployment configuration, TLS termination, rate limiting,
logging, and operational key management.

## Security properties implemented by the library

- Authorization Code is the only supported OIDC response/grant profile in the current adapter.
- OIDC authorization requests require `openid`, a non-empty bounded `nonce`, and PKCE `S256`.
- PKCE is required for confidential and public clients.
- League validates authorization code, client, redirect URI and PKCE proof before the code is
  redeemed; the adapter binds OIDC nonce and `max_age` metadata to the opaque authorization-code ID.
- Nonce metadata must be consumed exactly once by the host-provided metadata store. Missing,
  expired, or previously consumed metadata fails closed.
- ID Tokens are signed with RS256, have a bounded lifetime, contain an issuer, client audience,
  stable subject, nonce, issue/expiry times and `kid`, and reject identity attempts to override
  protocol-reserved claims.
- RSA signing and verification keys must be at least 2048 bits. The configured signing key pair
  must match. Retired keys are public-only and key IDs must be unique.
- JWKS generation publishes public RSA parameters only.
- UserInfo validates Bearer access tokens using League's `ResourceServer`, requires the `openid`
  scope and an end-user identifier, and returns the subject from the identity resolver.
- UserInfo and error responses use `Cache-Control: no-store` and `Pragma: no-cache`.
- Standard profile claims are filtered by granted scopes. Application-defined claims remain the
  host resolver's disclosure responsibility.
- Discovery metadata validates HTTPS endpoint URLs and rejects protocol capabilities outside the
  supported profile. Refresh tokens, logout and client registration are optional capabilities and
  are advertised only when enabled by the host.

## Host-application responsibilities

1. **Authorization transaction:** obtain the authorization request only through League's validated
   grant flow. Do not manufacture an approved `OidcAuthorizationRequest` from raw query parameters.
2. **Authentication and `max_age`:** inspect `OidcAuthorizationRequest::maxAge()` before approval.
   Re-authenticate when required. The token endpoint freshness check is only a fail-closed backstop.
3. **Request isolation:** create a request-/fiber-local `OidcRequestContextProviderInterface` for
   each HTTP request. Never share a mutable `RequestScopedOidcContextProvider` across concurrent
   requests or long-running worker jobs.
4. **Atomic persistence:** implement `AuthorizationCodeMetadataStoreInterface::consume()` as an
   atomic read-and-delete operation. Ensure authorization-code revocation is atomic under
   concurrent redemption. Use durable storage and expire metadata no later than its authorization
   code.
5. **Identity mapping:** use a stable, issuer-scoped, non-reassignable subject. The same subject
   must be returned from ID Token issuance and UserInfo for the same user/client pair. Do not use
   email addresses or sequential database IDs as public subjects.
6. **Claim disclosure:** enforce client-specific authorization for custom claims in the resolver.
   The built-in scope filter handles standard scope claims; it is not a policy engine for custom
   claims.
7. **Client security:** use exact redirect URI matching, strong client secrets, appropriate client
   authentication, secret rotation, and least privilege. Do not expose confidential client secrets
   to browsers or mobile applications.
8. **Transport and HTTP:** expose endpoints only over HTTPS; configure trusted proxy handling;
   avoid deriving issuer or endpoint URLs from untrusted `Host`/forwarded headers; set appropriate
   security headers; and apply rate limits and abuse monitoring.
9. **Key operations:** protect private keys with filesystem/secret-manager permissions; keep them
   out of source control, logs, backups accessible to untrusted operators, and JWKS; publish the
   new public key before signing with it; retain old public keys until every token signed by them
   has expired plus clock-skew, cache and deployment overlap.
10. **Errors and logs:** do not expose secrets, raw tokens, authorization codes, nonce values,
    private key material, or unnecessary personal data in logs or error pages.
11. **Token validation by clients:** relying parties must validate the signature using the trusted
    issuer's JWKS, pin the expected issuer, validate `aud` (and `azp` when applicable), check
    expiration and other time claims, and compare the returned nonce with the nonce from the
    original authentication request.

## Explicitly unsupported in the current profile

The library does not currently provide implicit or hybrid flows, request objects, PAR, JARM, session
management, encrypted ID Tokens, `form_post`, or FAPI profiles. Optional refresh-token, logout and
client-registration components are implemented and covered by automated tests across the library and
examples repositories, but remain disabled by default. They require host-owned durable storage,
policy, routing and (for Back-Channel Logout) delivery adapters. Review the relevant host adapters
before enabling them in a deployment.

## Security validation still required before production use

- Run the complete test suite on every supported PHP runtime (8.2, 8.3, 8.4 and 8.5) and supported
  dependency resolution.
- Run the OpenID Foundation OP conformance plans appropriate to the deployed host integration.
- Perform a deployment-specific threat model and penetration test covering routing, session/login,
  approval, client storage, database transactions, concurrency, proxy/TLS configuration, secrets,
  rate limiting and operational monitoring.
- Review dependency advisories and update dependencies through a controlled release process.

Passing this library's unit and integration tests does not establish OIDC conformance or production
readiness.
