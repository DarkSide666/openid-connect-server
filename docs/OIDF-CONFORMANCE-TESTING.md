# OpenID Foundation conformance testing

## Test target

The examples repository includes `reference-provider/`, a standalone, test-only HTTP OpenID Provider. It
allows the library to be exercised without another production application. It is a reference host, not part of the library's runtime API and not production-ready.

Deploy this reference provider (or another host that uses the library) to a dedicated hostname
with public HTTPS before starting an OpenID Foundation (OIDF) conformance run. The test target must
expose the discovery, authorization, token, JWKS and UserInfo endpoints advertised by its discovery
document, and must have the exact test client callback URI registered.

See [the reference-provider README](https://github.com/darkside666/openid-connect-server-examples/tree/main/reference-provider) for installation,
configuration, local HTTPS and deployment instructions.

## Current library profile

The default profile is Authorization Code flow with `response_type=code`,
`grant_type=authorization_code`, PKCE `S256`, RS256 ID Tokens, query response mode and UserInfo.
Optional refresh-token and logout flows are also exercised by the examples repository's independent
RP interoperability and security checks. Dynamic Client Registration has library and reference
provider tests, plus an interoperability check when registration protection is enabled. These checks
are separate from OIDF conformance testing; the optional modules are not part of the current OIDF
conformance deployment. Implicit/Hybrid flows, Request Objects, token encryption and non-RS256 signing
are not implemented by this profile.

Start with OIDC Core Basic OP tests and the applicable Configuration OP tests only after reviewing
the exact current test-plan requirements. The reference provider advertises only features it
currently wires. A test plan may still exercise optional or required behavior that this limited
reference host does not implement; record those outcomes rather than adding unsupported metadata or
loosening validation to force a pass.

## Procedure

1. Install and initialize the examples repository's `reference-provider/` using its README.
2. Deploy it at a stable public HTTPS origin. Set `OIDC_REFERENCE_BASE_URL` to the exact issuer URL.
3. Set the client ID, secret, token-endpoint authentication method and redirect URI to the values
   required by the chosen test plan. The redirect URI must match exactly.
4. Confirm that discovery, JWKS, authorization, token and UserInfo endpoints are externally
   reachable and that the issuer is identical in discovery and ID Tokens.
5. Open the OIDF conformance suite at `https://www.certification.openid.net/`, create a test plan,
   choose **Test an OpenID Provider**, and select only plans applicable to the supported profile.
6. Follow the plan instructions for browser interactions and test-client configuration.
7. Save the plan identifier, suite version/date, complete logs, warnings, skipped tests and failures.
   Remove secrets and personal data before sharing logs.
8. Fix failures in the library or reference host as appropriate, redeploy, and rerun affected tests.

The suite and its test plans evolve. Verify the current OIDF instructions and plan coverage before
each validation campaign. A test run is not formal certification; certification has a separate OIDF
submission process and may involve fees.

## References

- OIDF overview of the open-source conformance suite: <https://openid.net/certification/about-conformance-suite/>
- OIDC OpenID Provider testing instructions: <https://openid.net/certification/connect_op_testing/>
- OIDF certification information: <https://openid.net/Certification/>
- Conformance suite: <https://www.certification.openid.net/>
