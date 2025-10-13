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

    public function start(): void
    {
        $this->config->applyCookieParams();
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }
        $this->initializeSessionMeta();
        $this->validateSession();
    }

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

    public function regenerate(): void
    {
        if (session_status() === PHP_SESSION_ACTIVE) {
            $oldId = session_id();
            session_regenerate_id(true);
            $_SESSION['meta']['last_activity'] = time();
            $this->logger->write($this->buildLog('regenerate'));
        }
    }

    public function destroy(): void
    {
        $this->logger->write($this->buildLog('destroy'));
        $_SESSION = [];
        if (ini_get('session.use_cookies')) {
            $params = session_get_cookie_params();
            setcookie(session_name(), '', time() - 42000,
                $params['path'], $params['domain'],
                $params['secure'], $params['httponly']);
        }
        session_destroy();
    }

    private function validateSession(): void
    {
        // idle timeout
        $last = $_SESSION['meta']['last_activity'] ?? time();
        if ((time() - $last) > $this->config->idleTimeout) {
            $this->destroy();
            return;
        }
        // update last_activity
        $_SESSION['meta']['last_activity'] = time();

        // example anomaly detection comparing previous stored context - simplistic
        $context = $this->currentContext();
        $previousContext = $_SESSION['meta']['previous_context'] ?? null;
        $anoms = $this->anomalyDetector->detect($context, $previousContext);
        if (!empty($anoms)) {
            $this->logger->write($this->buildLog('anomaly', ['anomalies' => $anoms]));
            // you may terminate or flag session depending on policy
        }
        $_SESSION['meta']['previous_context'] = $context;
    }

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

    private function currentContext(): array
    {
        return [
            'ip' => $_SERVER['REMOTE_ADDR'] ?? null,
            'fingerprint' => $this->fingerprint()
        ];
    }

    private function fingerprint(): string
    {
        $ua = $_SERVER['HTTP_USER_AGENT'] ?? 'unknown';
        $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
        return hash('sha256', $ua . '|' . $ip);
    }

    // wrapper for set/get
    public function set(string $k, $v): void { $_SESSION[$k] = $v; }
    public function get(string $k) { return $_SESSION[$k] ?? null; }
}
