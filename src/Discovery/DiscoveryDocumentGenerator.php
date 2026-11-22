<?php

declare(strict_types=1);

namespace DarkSide\OpenIdConnectServer\Discovery;

final readonly class DiscoveryDocumentGenerator
{
    public function __construct(private ProviderMetadata $metadata)
    {
    }

    /** @return array<string, mixed> */
    public function generate(): array
    {
        $document = [
            'issuer' => $this->metadata->issuer,
            'authorization_endpoint' => $this->metadata->authorizationEndpoint,
            'token_endpoint' => $this->metadata->tokenEndpoint,
            'jwks_uri' => $this->metadata->jwksUri,
            'response_types_supported' => array_values(array_unique($this->metadata->responseTypes)),
            'response_modes_supported' => array_values(array_unique($this->metadata->responseModes)),
            'subject_types_supported' => ['public'],
            'id_token_signing_alg_values_supported' => ['RS256'],
            'scopes_supported' => array_values(array_unique($this->metadata->scopes)),
            'claims_supported' => array_values(array_unique($this->metadata->claims)),
            'grant_types_supported' => array_values(array_unique($this->metadata->grantTypes)),
            'token_endpoint_auth_methods_supported' => array_values(array_unique($this->metadata->tokenEndpointAuthMethods)),
            'code_challenge_methods_supported' => array_values(array_unique($this->metadata->codeChallengeMethods)),
        ];

        if ($this->metadata->userinfoEndpoint !== null) {
            $document['userinfo_endpoint'] = $this->metadata->userinfoEndpoint;
        }
        if ($this->metadata->endSessionEndpoint !== null) {
            $document['end_session_endpoint'] = $this->metadata->endSessionEndpoint;
        }
        if ($this->metadata->backchannelLogoutSupported) {
            $document['backchannel_logout_supported'] = true;
            $document['backchannel_logout_session_supported'] = $this->metadata->backchannelLogoutSessionSupported;
        }
        if ($this->metadata->registrationEndpoint !== null) {
            $document['registration_endpoint'] = $this->metadata->registrationEndpoint;
        }

        return $document;
    }
}
