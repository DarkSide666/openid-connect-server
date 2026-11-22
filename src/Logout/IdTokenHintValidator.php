<?php

declare(strict_types=1);

namespace DarkSide\OpenIdConnectServer\Logout;

use DateTimeImmutable;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Token\Plain;
use DarkSide\OpenIdConnectServer\Key\VerificationKey;

final readonly class IdTokenHintValidator
{
    /** @param list<VerificationKey> $keys */
    public function __construct(private string $issuer, private array $keys)
    {
    }

    /** @return array{client_id:string,sub:string,exp:int} */
    public function validate(string $jwt, ?DateTimeImmutable $now = null): array
    {
        if ($jwt === '') {
            throw new \InvalidArgumentException('ID Token hint must not be empty.');
        }
        $configuration = Configuration::forAsymmetricSigner(new Sha256(), InMemory::plainText('unused'), InMemory::plainText('unused'));
        try {
            $token = $configuration->parser()->parse($jwt);
        } catch (\Throwable $e) {
            throw new \InvalidArgumentException('Malformed ID Token hint.', 0, $e);
        }
        if (!$token instanceof Plain) {
            throw new \InvalidArgumentException('ID Token hint must be a signed JWT.');
        }
        $key = null;
        foreach ($this->keys as $candidate) {
            if ($candidate->keyId === $token->headers()->get('kid')) {
                $key = $candidate;
                break;
            }
        }
        if ($key === null || $key->publicKeyPem === '' || !$configuration->validator()->validate(
            $token,
            new \Lcobucci\JWT\Validation\Constraint\SignedWith(new Sha256(), InMemory::plainText($key->publicKeyPem)),
        )) {
            throw new \InvalidArgumentException('ID Token hint signature is invalid.');
        }
        $claims = $token->claims();
        $aud = $claims->get('aud');
        $subject = $claims->get('sub');
        $issuedBy = $claims->get('iss');
        $expiresAt = $claims->get('exp');
        $issuedAt = $claims->get('iat');
        $now ??= new DateTimeImmutable();
        if (
            $issuedBy !== $this->issuer || !is_array($aud) || count($aud) !== 1 || !is_string($aud[0] ?? null)
            || !is_string($subject) || $subject === '' || !$expiresAt instanceof DateTimeImmutable
            || !$issuedAt instanceof DateTimeImmutable || $issuedAt > $now->modify('+60 seconds')
        ) {
            throw new \InvalidArgumentException('ID Token hint claims are invalid.');
        }
        return ['client_id' => $aud[0], 'sub' => $subject, 'exp' => $expiresAt->getTimestamp()];
    }
}
