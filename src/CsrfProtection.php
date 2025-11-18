<?php
namespace SecureSession;

/**
 * CSRF Protection Manager
 * Generates and validates CSRF tokens to prevent Cross-Site Request Forgery attacks
 */
class CsrfProtection
{
    private const TOKEN_NAME = 'csrf_token';
    private const TOKEN_LENGTH = 32;
    private SessionManager $sessionManager;

    public function __construct(SessionManager $sessionManager)
    {
        $this->sessionManager = $sessionManager;
    }

    /**
     * Generate a new CSRF token and store it in the session
     * 
     * @return string The generated token
     */
    public function generateToken(): string
    {
        $token = bin2hex(random_bytes(self::TOKEN_LENGTH));
        $this->sessionManager->set(self::TOKEN_NAME, $token);
        return $token;
    }

    /**
     * Get the current CSRF token, generating one if it doesn't exist
     * 
     * @return string The CSRF token
     */
    public function getToken(): string
    {
        $token = $this->sessionManager->get(self::TOKEN_NAME);
        
        if (!$token) {
            $token = $this->generateToken();
        }
        
        return $token;
    }

    /**
     * Validate a CSRF token from user input
     * 
     * @param string|null $token The token to validate
     * @return bool True if valid, false otherwise
     */
    public function validateToken(?string $token): bool
    {
        if (empty($token)) {
            return false;
        }

        $sessionToken = $this->sessionManager->get(self::TOKEN_NAME);
        
        if (empty($sessionToken)) {
            return false;
        }

        // Use hash_equals to prevent timing attacks
        return hash_equals($sessionToken, $token);
    }

    /**
     * Validate CSRF token from POST request
     * Checks both POST data and custom header
     * 
     * @return bool True if valid, false otherwise
     */
    public function validateRequest(): bool
    {
        // Check POST data first
        $token = $_POST[self::TOKEN_NAME] ?? null;
        
        // Fallback to custom header (for AJAX requests)
        if (!$token) {
            $token = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? null;
        }

        return $this->validateToken($token);
    }

    /**
     * Validate and regenerate token (one-time use pattern)
     * Use this for critical operations
     * 
     * @param string|null $token The token to validate
     * @return bool True if valid, false otherwise
     */
    public function validateAndRegenerate(?string $token): bool
    {
        $isValid = $this->validateToken($token);
        
        if ($isValid) {
            $this->generateToken(); // Generate new token after use
        }
        
        return $isValid;
    }

    /**
     * Get HTML hidden input field with CSRF token
     * 
     * @return string HTML input field
     */
    public function getHiddenInput(): string
    {
        $token = htmlspecialchars($this->getToken(), ENT_QUOTES, 'UTF-8');
        return '<input type="hidden" name="' . self::TOKEN_NAME . '" value="' . $token . '">';
    }

    /**
     * Get meta tag for CSRF token (for AJAX requests)
     * 
     * @return string HTML meta tag
     */
    public function getMetaTag(): string
    {
        $token = htmlspecialchars($this->getToken(), ENT_QUOTES, 'UTF-8');
        return '<meta name="csrf-token" content="' . $token . '">';
    }

    /**
     * Verify request origin matches expected domain
     * Additional layer of protection beyond CSRF tokens
     * 
     * @param array $allowedOrigins List of allowed origin domains
     * @return bool True if origin is valid
     */
    public function validateOrigin(array $allowedOrigins = []): bool
    {
        $origin = $_SERVER['HTTP_ORIGIN'] ?? $_SERVER['HTTP_REFERER'] ?? '';
        
        if (empty($origin)) {
            // No origin header - might be same-origin request
            return true;
        }

        $originHost = parse_url($origin, PHP_URL_HOST);
        $currentHost = $_SERVER['HTTP_HOST'] ?? '';

        // Allow same-origin
        if ($originHost === $currentHost) {
            return true;
        }

        // Check against allowed origins
        foreach ($allowedOrigins as $allowed) {
            if ($originHost === $allowed) {
                return true;
            }
        }

        return false;
    }

    /**
     * Full CSRF protection check (token + origin)
     * 
     * @param array $allowedOrigins Optional list of allowed origins
     * @return bool True if request passes all checks
     */
    public function validateFull(array $allowedOrigins = []): bool
    {
        return $this->validateRequest() && $this->validateOrigin($allowedOrigins);
    }

    /**
     * Handle CSRF validation failure
     * Logs the attempt and returns appropriate response
     * 
     * @param bool $terminate Whether to terminate script execution
     * @return void
     */
    public function handleFailure(bool $terminate = true): void
    {
        // Log the CSRF attempt
        error_log(sprintf(
            'CSRF validation failed - IP: %s, User-Agent: %s, Referer: %s',
            $_SERVER['REMOTE_ADDR'] ?? 'unknown',
            $_SERVER['HTTP_USER_AGENT'] ?? 'unknown',
            $_SERVER['HTTP_REFERER'] ?? 'none'
        ));

        if ($terminate) {
            http_response_code(403);
            header('Content-Type: application/json');
            echo json_encode([
                'error' => 'CSRF validation failed',
                'message' => 'Invalid or missing CSRF token'
            ]);
            exit;
        }
    }
}