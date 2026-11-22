# Optional Protocol Modules

The library contains opt-in building blocks for RP-Initiated Logout, Back-Channel Logout,
`offline_access`, and Dynamic Client Registration. It does not mount routes or provide application
sessions, consent UI, database adapters, or an HTTP delivery client. A host must wire a module
explicitly and advertise only endpoints it actually serves.

## Refresh tokens and offline access

Pass `offlineAccessEnabled: true` as the final argument to `OidcAuthCodeGrant` only after configuring
the host's League client and scope repositories for the `refresh_token` grant and `offline_access`
scope. The grant rejects offline access without `prompt=consent`. The host must display and record
the consent represented by its approved authorization request.

Register `OidcRefreshTokenGrant` with the authorization server and configure its lifetime. League's
repository passed to `OidcRefreshTokenGrant` must implement
`RotatingRefreshTokenRepositoryInterface`, persist tokens durably and atomically, associate each newly
issued token with the current family during `beginRotation`/`endRotation`. Its
`consumeRefreshToken` operation must atomically distinguish a first use from replay. On replay,
`revokeFamilyForReusedToken` must durably revoke the whole family, including tokens created by a
concurrent in-flight rotation.
Do not log presented tokens. The refresh response omits an ID Token; OIDC
allows one to be omitted from refresh responses.

Advertise `offline_access` in `ProviderMetadata` only with `offlineAccessSupported: true` and the
`refresh_token` grant in `grantTypes`. Defaults continue to advertise authorization code only.

## Logout

Use `RpInitiatedLogoutService` to validate the hint, bind the client to its audience, and enforce an
exact match against that client's registered `post_logout_redirect_uris`. A redirect requires a
valid ID Token hint. A hint can outlive its ID Token expiry when it identifies a current or recent
OP session; the host must confirm that association or ask the user before acting. The returned
subject is a lookup value, not proof that an application session still exists.

For Back-Channel Logout, use `LogoutTokenIssuer` and `BackChannelLogoutService`. The host's
`LogoutClientStoreInterface` maps a subject/session to registered clients. Its delivery adapter must
POST `logout_token` as form data to each registered HTTPS endpoint and handle timeouts and failures.
`LogoutTokenValidator` checks signature, issuer, audience, time bounds, event shape and replay state.
Its `LogoutTokenReplayStoreInterface` implementation must reserve token IDs atomically until expiry.
`sid` is included in ID Tokens when the host supplies it through `OidcSessionIdProviderInterface`
for an authorization transaction or an identity implementing `SessionIdentityInterface`. Persist
the session ID with the authorization code; do not look it up later from mutable global session
state.

Advertise `end_session_endpoint` and Back-Channel Logout support only when the corresponding endpoint
and host adapters are active. Set `backchannelLogoutSessionSupported` only when session IDs are
available and `sid` appears in `claims`.

## Dynamic Client Registration

`ClientRegistrationService` validates the supported metadata subset, asks the host policy whether to
accept the registration, applies host provisioning, and persists the result through
`ClientRegistrationStoreInterface`. Wire it to a registration route only when registration is
intended. The policy must require an initial access token or apply another abuse-prevention policy
appropriate to the deployment and restrict allowed redirect origins and client types. The service
generates a one-time secret for confidential client authentication methods; the host must hash or
otherwise protect credentials at rest and return the secret only in the registration response. The initial module supports client creation;
it does not expose client configuration management endpoints.

## Discovery metadata

`ProviderMetadata` keeps all new features disabled by default. When enabling a feature, configure its
endpoint and supported scopes/grants consistently. Metadata validation rejects refresh-token
advertising unless the offline-access scope and grant are enabled together.
