# Signing-Key Configuration and Operations Review

This document explains the key material used by the library integration, how the reference provider keeps the key roles separate, and what the host application must control operationally. It reviews the existing implementation; it does not introduce a new key-management API or protocol feature.

## 1. There are three distinct kinds of key material

Do not treat every key used by the provider as an OIDC signing key. The current reference provider has three separate key roles:

| Key material | Purpose | Used by | Published in OIDC JWKS? |
|---|---|---|---|
| OAuth RSA private key | Signs League OAuth access tokens | League `AuthorizationServer` | No |
| OAuth RSA public key | Verifies League OAuth access tokens | League `ResourceServer` | No |
| OAuth encryption key | Encryption key supplied to League `AuthorizationServer` | League OAuth2 Server | No |
| OIDC RSA private key | Signs OIDC ID Tokens using RS256 | `IdTokenIssuer` | Never |
| OIDC RSA public key | Verifies ID Token signatures | `SigningKeySet` / `JwksGenerator` | Yes |

The OAuth private/public pair and the OIDC private/public pair serve different protocols and must remain separate. The OAuth encryption key is a third, unrelated secret; it is not a signing key and is not a public key.

In the reference provider, `ProviderFactory` makes this separation explicit:

- `oauth-private.pem` is passed to League's `AuthorizationServer`.
- `oauth-public.pem` is passed to League's `ResourceServer`.
- `oauth-encryption.key` is passed to League's `AuthorizationServer` as its encryption key.
- The OIDC key pair is loaded into `SigningKey`, then used by `IdTokenIssuer` and `SigningKeySet`.
- `JwksGenerator` publishes only the OIDC public key material.

Do not publish OAuth keys or either private key in the OIDC JWKS.

## 2. OIDC signing-key object relationships

The host application constructs the active `SigningKey` from a key ID and a matching RSA private/public PEM pair:

```php
$activeOidcSigningKey = new SigningKey(
    $keyId,
    $privateKeyPem,
    $publicKeyPem,
);

$idTokenIssuer = new IdTokenIssuer(
    $issuerIdentifier,
    $activeOidcSigningKey,
    300,
);

$oidcSigningKeySet = new SigningKeySet($activeOidcSigningKey);
$jwksGenerator = new JwksGenerator($oidcSigningKeySet);
```

Use the **same active `SigningKey` instance** for `IdTokenIssuer` and `SigningKeySet`. This keeps the key used to sign an ID Token aligned with the public key advertised in JWKS.

`SigningKey` validates that:

- The key ID contains 1–128 permitted URL-safe characters.
- The private key is a valid RSA PEM key.
- The public key is a valid RSA PEM key.
- The RSA modulus is at least 2048 bits.
- The private and public keys have matching RSA modulus and exponent values.

`SigningKeySet` validates that additional verification keys are `VerificationKey` instances and that all key IDs are unique within the set. `VerificationKey` accepts public-only RSA PEM material and enforces the same minimum RSA key size. `JwksGenerator` emits RSA signing JWKs with `use=sig`, `alg=RS256`, and the configured `kid`.

The `kid` in an issued ID Token's protected JOSE header must match the `kid` of the public JWK that verifies it. Do not reuse a `kid` for a different key pair, including after a key has been retired.

## 3. Issuer and active-key consistency

Two consistency rules are essential:

1. The issuer passed to `IdTokenIssuer` must exactly equal the issuer passed to `ProviderMetadata` and emitted by the discovery document.
2. The active `SigningKey` passed to `IdTokenIssuer` must be the same active key represented in the `SigningKeySet` passed to `JwksGenerator`.

The library accepts these objects independently; it does not create one central provider configuration object or automatically cross-check that separately constructed objects agree. The host application should load issuer and key settings from one configuration source and construct the related objects together in one composition root.

Add integration assertions that compare:

- The `iss` claim in a newly issued ID Token with discovery's `issuer` value.
- The ID Token header's `kid` with a `kid` in the published JWKS.
- The signature verification result using the public JWK selected by that `kid`.

Do not derive the issuer from an untrusted incoming `Host` or forwarded header. Configure the externally visible HTTPS issuer explicitly.

## 4. Key loading and private-key protection

The library accepts PEM strings; it does not provide file storage, secret-manager, KMS or HSM integration. The application is responsible for retrieving key material from an appropriate protected source and controlling its lifecycle.

The current `SigningKey` constructor calls `openssl_pkey_get_private()` without a passphrase parameter. Therefore, the current OIDC signing-key API expects private-key PEM that OpenSSL can load without a passphrase. This is an implementation limitation, not a promise of encrypted-PEM, KMS or HSM support. Do not assume that placing an encrypted PEM file at the configured path will work.

Operational guidance:

- Keep private keys outside the public document root and outside source control.
- Restrict filesystem access to the service account that needs the key.
- Use a secret-management/deployment process to provision the key; do not generate a new key on every request or application start.
- Avoid printing PEM contents, secrets or environment values in logs or exception messages.
- Ensure backups and disaster-recovery copies receive the same access controls as the live private key.
- Plan key compromise response separately from routine rotation.
- Keep the OIDC private key in memory only where required by the issuer; never expose it through discovery, JWKS, diagnostics or application routes.

If a deployment requires passphrase-protected private keys, remote signing, KMS or HSM-backed signing, that requirement is not supported by the current public API and must be evaluated as a separate architectural change rather than worked around by publishing private material or weakening key protection.

## 5. Reference-provider configuration mapping

The standalone reference provider is a local test fixture. Its configuration illustrates the separation but is not a production secret-management implementation.

| Setting / file | Role |
|---|---|
| `var/keys/oauth-private.pem` | League OAuth access-token signing private key |
| `var/keys/oauth-public.pem` | League OAuth access-token verification public key |
| `var/keys/oauth-encryption.key` | League OAuth encryption key |
| `var/keys/oidc-private.pem` | Default OIDC ID Token signing private key |
| `var/keys/oidc-public.pem` | Default OIDC ID Token verification public key |
| `OIDC_REFERENCE_OIDC_KEY_ID` | Active OIDC ID Token `kid` |
| `OIDC_REFERENCE_OIDC_PRIVATE_KEY_PATH` | Optional active OIDC private-key path |
| `OIDC_REFERENCE_OIDC_PUBLIC_KEY_PATH` | Optional active OIDC public-key path |
| `OIDC_REFERENCE_RETIRED_OIDC_KEYS` | Semicolon-separated `kid=public-key-path` entries added to JWKS |

`OIDC_REFERENCE_BASE_URL` is used as both the ID Token issuer and the discovery issuer in the reference provider. The factory also derives the advertised endpoint URLs from this configured origin. The value must be the externally reachable HTTPS origin and must not be inferred from the current request.

The setup script generates separate OAuth and OIDC RSA pairs and a separate OAuth encryption key. It does not overwrite existing keys. The reference provider's local files and `.env` must remain outside the web root and out of version control. Its file permissions and single-worker storage assumptions are for local testing only; production deployments need their own managed key provisioning and storage controls.

## 6. Safe OIDC key-rotation sequence

A rotation must preserve the ability to verify every still-valid ID Token. A safe sequence is:

1. Generate a new RSA key pair and assign it a never-before-used `kid`.
2. Validate the new pair before deployment. Keep the private half protected; only the public half is intended for JWKS.
3. Publish the new public key in JWKS while the old key remains active. Allow for JWKS cache and deployment propagation before issuing tokens with the new key.
4. Switch `IdTokenIssuer` to the new `SigningKey` and make that same key active in the `SigningKeySet`.
5. Keep the old public key in the verification set and JWKS while ID Tokens signed with it may still be valid.
6. Remove the old public key only after the maximum lifetime of old ID Tokens has elapsed, with additional allowance for accepted clock skew, JWKS cache lifetime and deployment propagation.
7. Securely retire or destroy the old private key according to the organization's key-retention and incident-response policy. Never publish it.

The `SigningKeySet` constructor takes the active `SigningKey` plus additional public-only `VerificationKey` instances. The additional list is named `retiredKeys` because its common use is retaining old verification keys; during a staged rollout, it can also hold a new public-only verification key before that key becomes active. The host application remains responsible for publishing the new key early enough and coordinating the switch.

A JWKS cache policy that is too long can delay relying parties from seeing a new key. Coordinate the JWKS HTTP cache lifetime, relying-party refresh behavior and rollout timing. Do not remove the old key merely because the provider has stopped signing with it.

The [Phase 6D.3 rotation procedure](https://github.com/darkside666/openid-connect-server-examples/blob/main/docs/PHASE-6D3-KEY-ROTATION.md) verifies the reference-provider implementation and independent RP behavior. It is a local test procedure, not a managed production rotation service.

## 7. Operational validation checklist

Before deploying a key change, verify all of the following:

- [ ] OAuth signing, OAuth verification, OAuth encryption and OIDC signing materials are distinct and correctly assigned.
- [ ] The active OIDC private/public pair matches.
- [ ] The OIDC RSA key is at least 2048 bits.
- [ ] The active `kid` is unique and matches between ID Token headers and JWKS.
- [ ] Discovery's issuer exactly matches the `iss` claim in newly issued ID Tokens.
- [ ] JWKS contains the active OIDC public key and no private parameters.
- [ ] JWKS contains old public keys for the full overlap period when required.
- [ ] The new public key is published and propagated before tokens are signed with it.
- [ ] The old public key is not removed before all corresponding ID Tokens have expired, including skew and cache allowances.
- [ ] Private keys and OAuth encryption material are excluded from web roots, source control, logs and public diagnostics.
- [ ] A recovery and compromised-key procedure exists and is tested.

The library provides key validation and JWKS generation. Key generation, secure storage, deployment, rotation scheduling, cache invalidation, backup, monitoring and incident response remain the host application's responsibility.
