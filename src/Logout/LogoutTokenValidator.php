<?php

declare(strict_types=1);

namespace DarkSide\OpenIdConnectServer\Logout;

use DateTimeImmutable;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Token\Plain;
use DarkSide\OpenIdConnectServer\Key\VerificationKey;

final readonly class LogoutTokenValidator
{
    /** @param list<VerificationKey> $keys */
    public function __construct(
        private string $issuer,
        private string $clientId,
        private array $keys,
        private LogoutTokenReplayStoreInterface $replayStore,
    ) {
        if ($issuer === '' || $clientId === '' || $keys === []) {
            throw new \InvalidArgumentException('Logout Token validation requires issuer, client ID, and verification keys.');
        }
    }

    /** @return array{iss:string,aud:string,iat:int,exp:int,jti:string,sub?:string,sid?:string} */
    public function validate(string $jwt, ?DateTimeImmutable $now = null): array
    {
        if ($jwt === '') {
            throw new \InvalidArgumentException('Logout Token must not be empty.');
        }
        $configuration = Configuration::forAsymmetricSigner(new Sha256(), InMemory::plainText('unused'), InMemory::plainText('unused'));
        try {
            $token = $configuration->parser()->parse($jwt);
        } catch (\Throwable $e) {
            throw new \InvalidArgumentException('Malformed Logout Token.', 0, $e);
        }
        if (!$token instanceof Plain) {
            throw new \InvalidArgumentException('Logout Token must be a signed JWT.');
        }
        $type = $token->headers()->get('typ');
        if (($type !== null && $type !== 'logout+jwt') || $token->headers()->get('alg') !== 'RS256') {
            throw new \InvalidArgumentException('Logout Token must use the logout+jwt type and RS256 algorithm.');
        }
        $parts = explode('.', $jwt);
        $rawClaims = isset($parts[1]) ? json_decode((string) base64_decode(strtr($parts[1], '-_', '+/'), true), false) : null;
        if (!$rawClaims instanceof \stdClass) {
            throw new \InvalidArgumentException('Logout Token payload must be a JSON object.');
        }
        $kid = $token->headers()->get('kid');
        $key = null;
        foreach ($this->keys as $candidate) {
            if ($candidate->keyId === $kid) {
                $key = $candidate;
                break;
            }
        }
        if ($key === null || $key->publicKeyPem === '' || !$configuration->validator()->validate(
            $token,
            new \Lcobucci\JWT\Validation\Constraint\SignedWith(
                new Sha256(),
                InMemory::plainText($key->publicKeyPem),
            ),
        )) {
            throw new \InvalidArgumentException('Logout Token signature is invalid.');
        }

        $claims = $token->claims();
        $iss = $claims->get('iss');
        $aud = $claims->get('aud');
        $iat = $claims->get('iat');
        $exp = $claims->get('exp');
        $jti = $claims->get('jti');
        $subject = $claims->get('sub', null);
        $sid = $claims->get('sid', null);
        $events = $claims->get('events', []);
        $rawEvents = $rawClaims->events ?? null;
        $now ??= new DateTimeImmutable();
        if (
            $iss !== $this->issuer || !is_array($aud) || !in_array($this->clientId, $aud, true)
            || !$iat instanceof DateTimeImmutable || !$exp instanceof DateTimeImmutable
            || $exp <= $now || $iat > $now->modify('+60 seconds')
            || $exp <= $iat
            || !is_string($jti) || $jti === ''
            || ((!is_string($subject) || $subject === '') && (!is_string($sid) || $sid === ''))
            || array_key_exists('nonce', $claims->all())
            || !is_array($events) || !$rawEvents instanceof \stdClass
            || !property_exists($rawEvents, 'http://schemas.openid.net/event/backchannel-logout')
            || !$rawEvents->{'http://schemas.openid.net/event/backchannel-logout'} instanceof \stdClass
        ) {
            throw new \InvalidArgumentException('Logout Token claims are invalid.');
        }
        if (!$this->replayStore->claim($this->issuer, $this->clientId, $jti, $exp)) {
            throw new \InvalidArgumentException('Logout Token replay detected.');
        }

        $result = ['iss' => $iss, 'aud' => $this->clientId, 'iat' => $iat->getTimestamp(), 'exp' => $exp->getTimestamp(), 'jti' => $jti];
        if (is_string($subject)) {
            $result['sub'] = $subject;
        }
        if (is_string($sid)) {
            $result['sid'] = $sid;
        }
        return $result;
    }
}
