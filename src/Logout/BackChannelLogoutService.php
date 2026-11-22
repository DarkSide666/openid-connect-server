<?php

declare(strict_types=1);

namespace DarkSide\OpenIdConnectServer\Logout;

final readonly class BackChannelLogoutService
{
    public function __construct(
        private LogoutClientStoreInterface $clients,
        private BackChannelLogoutDeliveryInterface $delivery,
        private LogoutTokenIssuer $issuer,
    ) {
    }

    public function notify(string $subject, ?string $sessionId = null): void
    {
        if ($subject === '' || ($sessionId !== null && $sessionId === '')) {
            throw new \InvalidArgumentException('Logout subject and session identifiers must not be empty.');
        }
        foreach ($this->clients->recipients($subject, $sessionId) as $recipient) {
            $uri = parse_url($recipient['logout_uri']);
            if (!is_array($uri) || strtolower((string) ($uri['scheme'] ?? '')) !== 'https' || empty($uri['host'])
                || isset($uri['user']) || isset($uri['pass']) || isset($uri['fragment'])) {
                throw new \UnexpectedValueException('Logout client store returned a non-HTTPS endpoint.');
            }
            if ($recipient['session_required'] && $sessionId === null) {
                continue;
            }
            $token = $this->issuer->issue($recipient['client_id'], $subject, $sessionId);
            $this->delivery->deliver($recipient['client_id'], $recipient['logout_uri'], $token);
        }
    }
}
