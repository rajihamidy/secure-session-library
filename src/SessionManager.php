<?php
namespace SecureSession;

class SessionManager
{
    private SecurityConfig $config;
    private Logger $logger;
    private AnomalyDetector $anomalyDetector;

    public function __construct(SecurityConfig $config, Logger $logger, AnomalyDetector $anomalyDetector)
    {
        $this->config = $config;
        $this->logger = $logger;
        $this->anomalyDetector = $anomalyDetector;
    }

    /**
     * Start a new secure session.
     * Handles cookie configuration, metadata initialization, and anomaly validation.
     */
    public function start(): void
    {
        // Skip session creation for CLI mode (e.g., PHPUnit)
        if (PHP_SAPI === 'cli' || PHP_SAPI === 'phpdbg') {
            return;
        }

        // Safely apply cookie params before starting session
        $this->config->applyCookieParams();

        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }

        $this->initializeSessionMeta();
        $this->validateSession();
    }

    /**
     * Initialize basic session metadata on first start.
     */
    private function initializeSessionMeta(): void
    {
        if (!isset($_SESSION['meta'])) {
            $_SESSION['meta'] = [
                'created_at' => gmdate('c'),
                'last_activity' => time(),
                'fingerprint' => $this->fingerprint()
            ];
            $this->logger->write($this->buildLog('create'));
        }
    }

    /**
     * Regenerate session ID and update forensic logs.
     * Returns array with old and new session IDs.
     */
    public function regenerate(bool $returnIds = true): array
    {
        if (PHP_SAPI === 'cli' || PHP_SAPI === 'phpdbg') {
            return ['old' => null, 'new' => null];
        }

        if (session_status() === PHP_SESSION_ACTIVE) {
            $oldId = session_id();
            session_regenerate_id(true);
            $newId = session_id();

            $_SESSION['meta']['last_activity'] = time();

            $this->logger->write($this->buildLog('regenerate', [
                'old_session_id' => $oldId,
                'new_session_id' => $newId
            ]));

            return $returnIds ? ['old' => $oldId, 'new' => $newId] : [];
        }

        return ['old' => null, 'new' => null];
    }

    /**
     * Securely destroy the session and log the action.
     */
    public function destroy(): void
    {
        $this->logger->write($this->buildLog('destroy'));

        if (PHP_SAPI === 'cli' || PHP_SAPI === 'phpdbg') {
            $_SESSION = [];
            return;
        }

        $_SESSION = [];
        if (ini_get('session.use_cookies')) {
            $params = session_get_cookie_params();
            setcookie(session_name(), '', time() - 42000,
                $params['path'], $params['domain'],
                $params['secure'], $params['httponly']
            );
        }
        session_destroy();
    }

    /**
     * Validate session activity, timeout, and anomalies.
     */
    private function validateSession(): void
    {
        // Skip validation in CLI mode (test environment)
        if (PHP_SAPI === 'cli' || PHP_SAPI === 'phpdbg') {
            return;
        }

        // idle timeout
        $last = $_SESSION['meta']['last_activity'] ?? time();
        if ((time() - $last) > $this->config->idleTimeout) {
            $this->destroy();
            return;
        }

        $_SESSION['meta']['last_activity'] = time();

        // anomaly detection
        $context = $this->currentContext();
        $previousContext = $_SESSION['meta']['previous_context'] ?? null;
        $anomalies = $this->anomalyDetector->detect($context, $previousContext);

        if (!empty($anomalies)) {
            $this->logger->write($this->buildLog('anomaly', ['anomalies' => $anomalies]));
        }

        $_SESSION['meta']['previous_context'] = $context;
    }

    /**
     * Build a structured forensic log entry.
     */
    private function buildLog(string $action, array $meta = []): array
    {
        return array_merge([
            'session_id' => session_id(),
            'user_id' => $_SESSION['user_id'] ?? null,
            'action' => $action,
            'ip' => $_SERVER['REMOTE_ADDR'] ?? null,
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? null,
            'fingerprint' => $this->fingerprint(),
            'meta' => $meta
        ]);
    }

    /**
     * Build context for anomaly detection.
     */
    private function currentContext(): array
    {
        return [
            'ip' => $_SERVER['REMOTE_ADDR'] ?? null,
            'fingerprint' => $this->fingerprint()
        ];
    }

    /**
     * Compute a session fingerprint using IP and User-Agent.
     */
    private function fingerprint(): string
    {
        $ua = $_SERVER['HTTP_USER_AGENT'] ?? 'unknown';
        $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
        return hash('sha256', $ua . '|' . $ip);
    }

    // Generic set/get wrappers for session variables
    public function set(string $key, $value): void
    {
        $_SESSION[$key] = $value;
    }

    public function get(string $key)
    {
        return $_SESSION[$key] ?? null;
    }
}
