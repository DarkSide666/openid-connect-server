# Persistence and Identity Integration Review

This document reviews the persistence and identity contracts exposed by `darkside/openid-connect-server`. It describes what a host application must implement and what the included reference provider demonstrates. It does not introduce new protocol behavior or change the library API.

## 1. Review outcome

The two existing extension points are sufficient for the current OIDC profile:

- `AuthorizationCodeMetadataStoreInterface` carries the OIDC nonce and optional `max_age` from authorization-code creation to redemption.
- `IdentityResolverInterface` maps League's authenticated resource-owner identifier to an OIDC subject, claims and authentication time.

No additional persistence abstraction or identity abstraction is recommended. The important work is implementing these contracts correctly in the host application's storage and account model.

The example repository's `FileAuthorizationCodeMetadataStore` and `IdentityResolver` are fixtures only. They are not production persistence or identity-management implementations.

## 2. Authorization-code metadata persistence

### Data being stored

For each authorization code, the library stores an `AuthorizationCodeMetadata` value containing:

- `nonce`: the nonce supplied in the OIDC authorization request;
- `expiresAt`: the authorization code's expiry time;
- `maxAge`: the optional `max_age` request value.

The store is keyed by League's opaque authorization-code identifier, not by the raw authorization-code string. The host application must not substitute a browser-provided value for that identifier.

### Required store behavior

An implementation of `AuthorizationCodeMetadataStoreInterface` must satisfy all of the following:

1. **Unique insert:** `store()` must reject a second record for the same authorization-code identifier. A primary key or equivalent uniqueness constraint is appropriate.
2. **Bounded lifetime:** metadata must not remain usable after `expiresAt`. Configure a TTL no later than the authorization code's expiry. Expired records should also be physically cleaned up according to the storage system's retention policy.
3. **Atomic consume:** `consume()` must retrieve and delete a record as one indivisible operation. Two concurrent token requests must never both receive the same nonce metadata.
4. **One-time result:** after one successful consume, every later consume for that identifier must return `null`.
5. **Fail closed:** missing, malformed, expired or already-consumed metadata must not be replaced with a generated nonce or treated as a successful OIDC transaction.
6. **Shared durability:** authorization and token requests may reach different PHP processes or hosts. The store must therefore be shared by every application instance that can handle those requests; process-local arrays are not sufficient.
7. **Failure propagation:** storage failures must be surfaced. Do not silently continue token issuance when metadata cannot be consumed.

Nonce values are transaction data. Keep the store outside the public web root, restrict access, use a bounded retention period and avoid writing nonce values to application logs.

### Database implementation pattern

A relational implementation can use a table similar to:

```sql
CREATE TABLE oidc_authorization_code_metadata (
    authorization_code_id VARCHAR(128) PRIMARY KEY,
    nonce VARCHAR(256) NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    max_age INTEGER NULL
);
```

The primary key enforces uniqueness. `store()` inserts one row and sets its expiry to the authorization code's expiry.

For a database with row-level locking, implement `consume()` in one transaction:

1. Begin a transaction.
2. Select the row by authorization-code identifier using `SELECT ... FOR UPDATE`.
3. Delete the row while the lock is held.
4. Commit the transaction.
5. Return the values only if the row existed and had not expired; otherwise return `null`.

Use the database's equivalent atomic primitive if its SQL dialect differs. A plain `SELECT` followed by an uncoordinated `DELETE` is not safe. Some databases support a single atomic `DELETE ... RETURNING`, which can also implement the contract.

For Redis or another key/value store, use an atomic get-and-delete operation (or a server-side script providing the same guarantee) and set the key's TTL to no later than the authorization-code expiry. Do not implement consume as separate client-side `GET` and `DEL` calls.

### Relationship to League's authorization-code repository

`OidcAuthCodeRepository` decorates the application's League `AuthCodeRepositoryInterface`:

- When a code is created, it asks the inner repository to persist the code, then stores the OIDC metadata.
- If metadata persistence fails, it attempts to revoke the newly persisted code and propagates the failure.
- During redemption, it consumes the metadata and attaches the nonce and `max_age` to the current request context. Missing or expired metadata causes the OIDC exchange to fail closed.

The library does not wrap the host's authorization-code repository and metadata store in one cross-store database transaction. The host's League repository must provide reliable persistence, revocation and single-use redemption semantics. If the code repository and metadata store use different systems, ensure the compensation path (revoking a code after metadata-store failure) is reliable and test it under failure conditions.

### What the reference store proves—and what it does not

The example repository's `reference-provider/src/Storage/FileAuthorizationCodeMetadataStore.php` delegates to `FileState`, which uses an exclusive `flock()` around the read/modify/write operation. That serializes store and consume operations among processes sharing the same local file and filesystem lock implementation. It deletes a record while holding the lock, so sequential consumers cannot both obtain it.

The reference implementation is intentionally limited:

- It is suitable only for the local, single-host test fixture, not a multi-host deployment or a distributed filesystem without verified locking semantics.
- It rewrites a JSON file in place and does not provide database-grade crash recovery or operational observability.
- Expired records are rejected when consumed, but there is no background expiry cleanup; an expired, never-consumed record can remain in the file.
- The current PHPUnit test verifies one-time consumption across two store instances sequentially. It does not itself create a simultaneous multi-process race.

A production adapter should use the application's durable shared store and add an integration test that exercises simultaneous consumers against the actual storage engine.

## 3. Identity resolution

### Inputs supplied to the resolver

`IdentityResolverInterface::resolve()` receives:

- `userIdentifier`: the end-user identifier associated with the validated League access token;
- `clientId`: the client identifier associated with that token;
- `grantedScopes`: the scopes actually granted to the token.

The resolver should look up the current account state using the application identifier. It should not trust a user identifier supplied independently by a UserInfo request. The UserInfo endpoint validates the bearer token first and obtains these values from the validated request.

### Subject (`sub`) requirements

`IdentityInterface::subject()` must return a stable, opaque identifier for the user within this issuer.

- Do not use an email address, phone number, mutable username or sequential database primary key.
- Persist a dedicated random/opaque OIDC subject mapping, or use an existing immutable opaque identifier whose lifecycle is controlled.
- Do not regenerate the subject when a user changes their email, display name or username.
- Return the same subject for the same user in the ID Token and UserInfo responses. The library calls the resolver independently at token issuance and at UserInfo time; it cannot repair inconsistent application mappings.
- Define what happens when an account is merged, renamed, disabled or deleted. Do not accidentally reassign an old subject to a different person.

The current library contract describes an issuer-scoped stable subject. The presence of `clientId` in the resolver signature allows client-specific claim-disclosure decisions; it does not by itself implement OpenID Connect pairwise-subject rules. Do not vary `sub` by client unless the host application deliberately designs and validates a complete pairwise-subject policy.

### Claims and disclosure policy

The resolver is responsible for deciding which application-defined claims a client may receive. Use both `grantedScopes` and the application's client/user disclosure policy. The library applies defense-in-depth filtering to standard OIDC claims associated with `profile`, `email`, `address` and `phone` scopes, but it cannot infer the authorization policy for custom claims.

Do not return protocol-controlled claims such as `iss`, `sub`, `aud`, `exp`, `iat`, `nonce`, `auth_time` or other reserved token claims in `claims()`. The provider creates those itself and rejects attempts to override reserved claims.

Validate values before returning them. Standard OIDC claims have defined JSON types; for example, `email_verified` is boolean, common profile fields are strings, and `updated_at` is a NumericDate. Avoid placing internal account data, secrets or unnecessary personal information in the claim set.

### Authentication time and `max_age`

`IdentityInterface::authTime()` must represent the time the end user actually authenticated, not the time the access token was issued, the time the resolver ran, or merely the time a PHP session was created.

When an authorization request contains `max_age`, the host application must inspect it during the authorization interaction and require re-authentication when the existing authentication is too old. The returned identity must expose the resulting authentication time. The ID Token issuer performs a fail-closed freshness check; it does not perform login or re-authentication. If a required authentication time is unavailable, token issuance fails rather than inventing one.

Store authentication time per user authentication/session as appropriate for the application. A single global “last login” timestamp is not suitable for a multi-user production provider.

### Account lifecycle and errors

Resolve only accounts that are currently eligible to authenticate. Decide how disabled, deleted, locked or merged accounts are handled. UserInfo may be requested after the original login, so the resolver must apply the application's current disclosure and account-status policy at that time too.

Do not return a different `sub` or silently substitute another user if an account lookup fails. Raise an application-level error and let the HTTP host map it to a safe response without disclosing internal account details. Logging should contain a correlation identifier and safe diagnostic context, not tokens or unnecessary claim values.

## 4. Reference-provider identity limitations

The reference provider deliberately contains one test user and one test client. Its `IdentityResolver` returns a fixed subject and fixed example claims, and its authentication-time store holds one fixture timestamp. It is useful for exercising the library contract but does not demonstrate:

- production user lookup or account lifecycle checks;
- multiple-client disclosure policy;
- persistent subject allocation or migration;
- per-user/per-session authentication time;
- pairwise subjects;
- real consent or claim-release policy.

Do not copy the reference resolver or authentication-time store into a production application.

## 5. Integration test checklist for a host application

Before deploying a concrete adapter, test it against the actual database/cache and identity model.

### Metadata store

- Duplicate `store()` for the same authorization-code ID is rejected.
- A record cannot be consumed after its expiry.
- A successful consume returns the metadata exactly once.
- Two simultaneous consumers result in exactly one successful return.
- Metadata-store failure prevents a usable authorization code from being issued or redeemed.
- Failure to persist metadata triggers reliable authorization-code revocation.
- Expired records are cleaned up according to the storage retention policy.
- Separate application instances can read and consume the same record.

### Identity resolver

- The same account always maps to the same subject across token issuance and UserInfo.
- Subject values are opaque, stable and never recycled for another account.
- Client and granted-scope policy controls standard and custom claims as intended.
- No reserved protocol claims can be supplied by the application resolver.
- `authTime()` is accurate for the authenticating user/session.
- `max_age` causes re-authentication when needed and fails closed if authentication time is unavailable.
- Disabled/deleted accounts are handled according to policy, including when UserInfo is called later.
- Changes to email, username or profile data do not change the subject.

## 6. Review conclusion

The current interfaces are adequate for the library's deliberately limited OIDC profile. The critical responsibilities—durable one-time metadata consumption, stable subject mapping, claim disclosure and accurate authentication time—belong to the integrating application. No library API expansion is recommended as part of this review.
