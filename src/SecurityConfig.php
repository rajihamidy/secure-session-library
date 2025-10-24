<?php
namespace SecureSession;

class SecurityConfig
{
    public int $idleTimeout = 300; // seconds
    public ?int $absoluteTimeout = 86400; // optional absolute expiry
    public string $sameSite = 'Lax'; // 'Strict' | 'Lax' | 'None' mitigates CSRF attacks
    public bool $secureCookie = true;
    public bool $httpOnly = true;
    public string $cookiePath = '/';
    public ?string $cookieDomain = null;

    /**
     * Apply secure cookie parameters safely.
     * Skips cookie configuration if headers already sent
     * or running in CLI mode (e.g., PHPUnit testing).
     * httponly = true → prevents JavaScript access (protects against XSS)
    * secure = true → ensures cookies are sent only over HTTPS
    * samesite = 'Strict' or 'Lax' → mitigates CSRF attacks
    * path and domain restrictions → limits cookie scope
     */
    public function applyCookieParams(): void
    {
        // Skip cookie configuration if running in CLI (no HTTP headers)
        if (PHP_SAPI === 'cli' || PHP_SAPI === 'phpdbg') {
            return;
        }

        // Skip if headers already sent or session already active
        if (headers_sent() || session_status() === PHP_SESSION_ACTIVE) {
            return;
        }

        // Determine if secure cookie flag should be true
        $secure = $this->secureCookie && (
            (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
        );

        // Safely set cookie parameters
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
