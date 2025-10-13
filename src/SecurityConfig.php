<?php
namespace SecureSession;

class SecurityConfig
{
    public int $idleTimeout = 900; // seconds
    public ?int $absoluteTimeout = 86400; // optional absolute expiry
    public string $sameSite = 'Lax'; // 'Strict' | 'Lax' | 'None'
    public bool $secureCookie = true;
    public bool $httpOnly = true;
    public string $cookiePath = '/';
    public ?string $cookieDomain = null;

    public function applyCookieParams(): void
    {
        $secure = $this->secureCookie && (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off');
        session_set_cookie_params([
            'lifetime' => $this->idleTimeout,
            'path' => $this->cookiePath,
            'domain' => $this->cookieDomain,
            'secure' => $secure,
            'httponly' => $this->httpOnly,
            'samesite' => $this->sameSite
        ]);
    }
}
