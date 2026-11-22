<?php

declare(strict_types=1);

namespace DarkSide\OpenIdConnectServer\Key;

final readonly class SigningKeySet
{
    /** @var list<VerificationKey> Public-only keys retained while previously issued tokens may still be used. */
    public array $retiredKeys;

    /**
     * @param array<mixed> $retiredKeys
     */
    public function __construct(public SigningKey $activeKey, array $retiredKeys = [])
    {
        if (!array_is_list($retiredKeys)) {
            throw new \InvalidArgumentException('Retired verification keys must be provided as a list.');
        }

        $validatedKeys = [];
        $ids = [$activeKey->keyId];
        foreach ($retiredKeys as $key) {
            if (!$key instanceof VerificationKey) {
                throw new \InvalidArgumentException('Retired keys must be VerificationKey instances.');
            }
            $validatedKeys[] = $key;
            $ids[] = $key->keyId;
        }

        if (count($ids) !== count(array_unique($ids))) {
            throw new \InvalidArgumentException('Key IDs must be unique within a key set.');
        }

        $this->retiredKeys = $validatedKeys;
    }

    /** @return list<VerificationKey> */
    public function verificationKeys(): array
    {
        return [new VerificationKey($this->activeKey->keyId, $this->activeKey->publicKeyPem), ...$this->retiredKeys];
    }
}
