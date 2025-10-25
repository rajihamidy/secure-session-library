<?php
namespace SecureSession;

class SecurityConfig
{
    public int $idleTimeout = 300; // seconds (e.g., 5 minutes)
    public ?int $absoluteTimeout = 86400; // optional absolute expiry
    public string $sameSite = 'Lax'; // 'Strict' | 'Lax' | 'None' mitigates CSRF attacks
    public bool $secureCookie = true;
    public bool $httpOnly = true;
    public string $cookiePath = '/';
    public ?string $cookieDomain = null;

    // New properties for idle logout automation
    public bool $autoInjectIdleScript = true; // enable JS-based auto logout
    public string $logoutEndpoint = '/demo.php'; // endpoint to handle logout

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

    /**
     * Injects JavaScript for client-side idle detection and automatic logout.
     * This script runs in every page that starts a session.
     * It detects inactivity based on user mouse and keyboard events
     * and triggers logout after the configured idle timeout.
     */
    public function injectIdleLogoutScript(): void
    {
        if (PHP_SAPI === 'cli' || PHP_SAPI === 'phpdbg' || headers_sent()) {
            return; // Skip injection during CLI or testing
        }

        if (!$this->autoInjectIdleScript) {
            return; // Disabled manually
        }

        $timeoutMs = $this->idleTimeout * 1000;
        $logoutUrl = htmlspecialchars($this->logoutEndpoint, ENT_QUOTES, 'UTF-8');
        $timeoutMin = round($this->idleTimeout / 60, 1);

        echo <<<HTML
<script>
(function() {
    let idleTimer;
    const idleLimit = {$timeoutMs};

    function resetTimer() {
        clearTimeout(idleTimer);
        idleTimer = setTimeout(triggerLogout, idleLimit);
    }

    function triggerLogout() {
        fetch('{$logoutUrl}', { method: 'POST' })
            .then(() => {
                alert('You have been logged out due to {$timeoutMin} minutes of inactivity.');
                window.location.href = '{$logoutUrl}';
            })
            .catch(() => {
                console.warn('Auto logout failed to reach server.');
            });
    }

    // Reset timer on user activity
    ['mousemove', 'keypress', 'click', 'scroll'].forEach(evt =>
        document.addEventListener(evt, resetTimer, false)
    );

    // Initialize timer when page loads
    window.onload = resetTimer;
})();
</script>
HTML;
    }
}
