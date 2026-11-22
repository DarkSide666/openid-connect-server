<?php

declare(strict_types=1);

namespace DarkSide\OpenIdConnectServer\Identity;

/**
 * Applies the standard OIDC scope-to-claim rules to claims returned by the host.
 * Application-defined claims remain the resolver's responsibility and must only
 * be returned when authorized by the host application's disclosure policy.
 */
final class ScopeClaimFilter
{
    /** @var array<string, list<string>> */
    private const CLAIMS_BY_SCOPE = [
        'profile' => [
            'name', 'family_name', 'given_name', 'middle_name', 'nickname',
            'preferred_username', 'profile', 'picture', 'website', 'gender',
            'birthdate', 'zoneinfo', 'locale', 'updated_at',
        ],
        'email' => ['email', 'email_verified'],
        'address' => ['address'],
        'phone' => ['phone_number', 'phone_number_verified'],
    ];

    /**
     * @param array<string, mixed> $claims
     * @param list<string> $grantedScopes
     * @return array<string, mixed>
     */
    public function filter(array $claims, array $grantedScopes): array
    {
        $allowed = [];
        foreach ($grantedScopes as $scope) {
            foreach (self::CLAIMS_BY_SCOPE[$scope] ?? [] as $claim) {
                $allowed[$claim] = true;
            }
        }

        foreach (array_keys($claims) as $claim) {
            foreach (self::CLAIMS_BY_SCOPE as $scopeClaims) {
                if (in_array($claim, $scopeClaims, true) && !isset($allowed[$claim])) {
                    unset($claims[$claim]);
                    break;
                }
            }
        }

        return $claims;
    }
}
