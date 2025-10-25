<?php
namespace SecureSession;

class SessionManager
{
    private SecurityConfig $config;
    private Logger $logger;
    private AnomalyDetector $anomalyDetector;
    private bool $testMode = false;

    public function __construct(SecurityConfig $config, Logger $logger, AnomalyDetector $anomalyDetector, bool $testMode = false)
    {
        $this->config = $config;
        $this->logger = $logger;
        $this->anomalyDetector = $anomalyDetector;
        $this->testMode = $testMode;
    }

    /**
     * Check if running in CLI mode and not in test mode
     */
    private function shouldSkipSessionOps(): bool
    {
        return (PHP_SAPI === 'cli' || PHP_SAPI === 'phpdbg') && !$this->testMode;
    }

    /**
     * Start a new secure session.
     * Handles cookie configuration, metadata initialization, and anomaly validation.
     */
    public function start(): void
    {
        // Check if running in CLI mode and not in test mode
        if ($this->shouldSkipSessionOps()) {
            return;
        }

        // Safely apply cookie params before starting session
        if (!$this->testMode) {
            $this->config->applyCookieParams();
        }

        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }

        // Initialize session metadata FIRST (this logs 'create' action)
        $this->initializeSessionMeta();
        
        // THEN check for timeout (only after meta is initialized)
        if (!$this->checkSessionTimeout()) {
            // Session was destroyed due to timeout
            return;
        }
        
        // Finally, validate session for anomalies
        $this->validateSession();

    // Inject client-side idle logout timer globally
    $this->config->injectIdleLogoutScript();
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
        if ($this->shouldSkipSessionOps()) {
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

        if ($this->shouldSkipSessionOps()) {
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
     * Check if session has exceeded idle timeout.
     * Returns false if session was destroyed, true if still valid.
     */
    private function checkSessionTimeout(): bool
    {
        // Only check timeout if session metadata and last_activity exist
        if (!isset($_SESSION['meta']['last_activity'])) {
            // New session, no timeout check needed
            return true;
        }

        $lastActivity = $_SESSION['meta']['last_activity'];
        $idleTime = time() - $lastActivity;
        
        // If idle time exceeds configured timeout, destroy session
        if ($idleTime > $this->config->idleTimeout) {
            // Log the timeout event
            $this->logger->write($this->buildLog('timeout', [
                'idle_seconds' => $idleTime,
                'timeout_limit' => $this->config->idleTimeout,
                'reason' => 'Session exceeded idle timeout',
                'last_activity' => date('Y-m-d H:i:s', $lastActivity),
                'current_time' => date('Y-m-d H:i:s')
            ]));
            
            // Destroy the session
            $this->destroy();
            
            // Return false to indicate session was destroyed
            return false;
        }
        
        // Session is still valid - update last activity timestamp
        $_SESSION['meta']['last_activity'] = time();
        return true;
    }

    /**
     * Validate session activity, timeout, and anomalies.
     */
    private function validateSession(): void
    {
        // Skip validation in CLI mode (test environment) unless in test mode
        if ($this->shouldSkipSessionOps()) {
            return;
        }

        // Anomaly detection (only in web context, not CLI)
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
            'session_id' => session_id() ?: 'cli_session_' . uniqid(),
            'user_id' => $_SESSION['user_id'] ?? null,
            'action' => $action,
            'ip' => $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1',
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'CLI',
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
            'ip' => $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1',
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