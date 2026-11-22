<?php

declare(strict_types=1);

namespace DarkSide\OpenIdConnectServer\Endpoint;

use InvalidArgumentException;
use JsonException;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\ResourceServer;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use DarkSide\OpenIdConnectServer\Identity\IdentityResolverInterface;
use DarkSide\OpenIdConnectServer\Identity\ScopeClaimFilter;

/**
 * Framework-independent OpenID Connect UserInfo endpoint.
 *
 * The endpoint validates Bearer access tokens through League's ResourceServer.
 * It deliberately accepts a PSR-7 response from the host application rather
 * than depending on a concrete HTTP message implementation.
 */
final readonly class UserInfoEndpoint
{
    private const RESERVED_CLAIMS = [
        'iss', 'aud', 'exp', 'iat', 'nbf', 'jti', 'nonce', 'azp',
        'at_hash', 'c_hash', 's_hash', 'auth_time', 'acr', 'amr', 'sid',
        'sub',
    ];

    public function __construct(
        private ResourceServer $resourceServer,
        private IdentityResolverInterface $identityResolver,
        private ScopeClaimFilter $scopeClaimFilter = new ScopeClaimFilter(),
    ) {
    }

    public function handle(ServerRequestInterface $request, ResponseInterface $response): ResponseInterface
    {
        if (!in_array(strtoupper($request->getMethod()), ['GET', 'POST'], true)) {
            return $this->writeJson(
                $response->withStatus(405)->withHeader('Allow', 'GET, POST'),
                ['error' => 'method_not_allowed'],
            );
        }

        try {
            $validatedRequest = $this->resourceServer->validateAuthenticatedRequest($request);
        } catch (OAuthServerException $exception) {
            return $exception->generateHttpResponse($response)
                ->withHeader('Cache-Control', 'no-store')
                ->withHeader('Pragma', 'no-cache');
        }

        $scopes = $validatedRequest->getAttribute('oauth_scopes', []);
        if (!is_array($scopes) || !$this->isStringList($scopes)) {
            return $this->writeJson($response->withStatus(401), ['error' => 'invalid_token']);
        }
        /** @var list<string> $scopes */

        if (!in_array('openid', $scopes, true)) {
            return $this->writeJson(
                $response
                    ->withStatus(403)
                    ->withHeader('WWW-Authenticate', 'Bearer error="insufficient_scope", scope="openid"'),
                ['error' => 'insufficient_scope'],
            );
        }

        $userIdentifier = $validatedRequest->getAttribute('oauth_user_id');
        $clientId = $validatedRequest->getAttribute('oauth_client_id');
        if (!is_string($userIdentifier) || $userIdentifier === '' || !is_string($clientId) || $clientId === '') {
            return $this->writeJson(
                $response->withStatus(403),
                ['error' => 'access_denied'],
            );
        }

        $identity = $this->identityResolver->resolve($userIdentifier, $clientId, $scopes);
        $subject = $identity->subject();
        if (strlen($subject) < 1 || strlen($subject) > 255 || preg_match('/^[\x21-\x7E]+$/D', $subject) !== 1) {
            throw new InvalidArgumentException('The UserInfo subject must contain 1-255 printable ASCII characters.');
        }

        $claims = $this->scopeClaimFilter->filter($identity->claims(), $scopes);
        $this->validateClaims($claims);
        $claims = ['sub' => $subject] + $claims;

        try {
            return $this->writeJson($response->withStatus(200), $claims);
        } catch (JsonException $exception) {
            throw new InvalidArgumentException('The resolved UserInfo claims could not be encoded as JSON.', 0, $exception);
        }
    }

    /** @param array<string, mixed> $claims */
    private function validateClaims(array $claims): void
    {
        foreach ($claims as $name => $value) {
            if ($name === '' || in_array($name, self::RESERVED_CLAIMS, true)) {
                throw new InvalidArgumentException(sprintf('Identity attempted to provide reserved or invalid UserInfo claim "%s".', (string) $name));
            }

            if (!$this->isJsonValue($value)) {
                throw new InvalidArgumentException(sprintf('UserInfo claim "%s" is not JSON-compatible.', $name));
            }
        }

        $stringClaims = [
            'name', 'family_name', 'given_name', 'middle_name', 'nickname',
            'preferred_username', 'profile', 'picture', 'website', 'gender',
            'birthdate', 'zoneinfo', 'locale', 'email', 'phone_number',
        ];
        foreach ($stringClaims as $claim) {
            if (isset($claims[$claim]) && !is_string($claims[$claim])) {
                throw new InvalidArgumentException(sprintf('OIDC claim "%s" must be a string.', $claim));
            }
        }

        foreach (['email_verified', 'phone_number_verified'] as $claim) {
            if (isset($claims[$claim]) && !is_bool($claims[$claim])) {
                throw new InvalidArgumentException(sprintf('OIDC claim "%s" must be a boolean.', $claim));
            }
        }

        if (isset($claims['updated_at']) && !is_int($claims['updated_at']) && !is_float($claims['updated_at'])) {
            throw new InvalidArgumentException('OIDC claim "updated_at" must be a NumericDate.');
        }

        if (isset($claims['address']) && (!is_array($claims['address']) || array_is_list($claims['address']))) {
            throw new InvalidArgumentException('OIDC claim "address" must be an object-shaped array.');
        }
    }

    private function isJsonValue(mixed $value): bool
    {
        if ($value === null || is_string($value) || is_bool($value) || is_int($value)) {
            return true;
        }
        if (is_float($value)) {
            return is_finite($value);
        }
        if (!is_array($value)) {
            return false;
        }
        foreach ($value as $item) {
            if (!$this->isJsonValue($item)) {
                return false;
            }
        }
        return true;
    }

    /** @param array<string, mixed> $payload */
    private function writeJson(ResponseInterface $response, array $payload): ResponseInterface
    {
        $json = json_encode($payload, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
        $response->getBody()->write($json);

        return $response
            ->withHeader('Content-Type', 'application/json; charset=utf-8')
            ->withHeader('Cache-Control', 'no-store')
            ->withHeader('Pragma', 'no-cache');
    }

    /**
     * @param array<mixed> $values
     * @phpstan-assert-if-true list<string> $values
     */
    private function isStringList(array $values): bool
    {
        if (!array_is_list($values)) {
            return false;
        }
        foreach ($values as $value) {
            if (!is_string($value) || $value === '') {
                return false;
            }
        }
        return true;
    }
}
