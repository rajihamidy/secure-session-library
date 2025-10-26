<?php
namespace SecureSession\Storage;

use PDO;

class SqliteStorage implements StorageInterface
{
    private PDO $pdo;
    private string $dbPath;

    public function __construct(string $file = null)
    {
        // If no path provided, use default location
        if ($file === null) {
            $file = $this->getDefaultDatabasePath();
        }
        
        $this->dbPath = $file;
        
        // Ensure the directory exists before creating database
        $this->ensureDirectoryExists(dirname($file));
        
        // Initialize database connection
        $this->pdo = new PDO('sqlite:' . $file);
        $this->pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        
        // Create tables if they don't exist
        $this->init();
    }

    /**
     * Get the default database path
     * Tries multiple locations in order of preference
     */
    private function getDefaultDatabasePath(): string
    {
        // Option 1: Use system temp directory (always writable)
        $tempDir = sys_get_temp_dir() . '/secure-session-library';
        if ($this->ensureDirectoryExists($tempDir)) {
            return $tempDir . '/session_logs.sqlite';
        }

        // Option 2: Try current working directory
        $cwd = getcwd() . '/data';
        if ($this->ensureDirectoryExists($cwd)) {
            return $cwd . '/session_logs.sqlite';
        }

        // Option 3: Use library's data directory (for development)
        $libData = __DIR__ . '/../../data';
        if ($this->ensureDirectoryExists($libData)) {
            return $libData . '/session_logs.sqlite';
        }

        // Fallback: Use temp directory without subdirectory
        return sys_get_temp_dir() . '/session_logs.sqlite';
    }

    /**
     * Ensure a directory exists, create it if it doesn't
     * Returns true if directory exists or was created successfully
     */
    private function ensureDirectoryExists(string $dir): bool
    {
        if (is_dir($dir)) {
            return is_writable($dir);
        }

        // Try to create the directory
        if (@mkdir($dir, 0755, true)) {
            return true;
        }

        // If creation failed, check if it was created by another process
        return is_dir($dir) && is_writable($dir);
    }

    /**
     * Initialize database schema
     */
    private function init(): void
    {
        $this->pdo->exec("
            CREATE TABLE IF NOT EXISTS session_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT,
                user_id TEXT,
                action TEXT,
                ip TEXT,
                user_agent TEXT,
                fingerprint TEXT,
                meta TEXT,
                created_at TEXT,
                hmac TEXT
            )
        ");

        // Create index for faster queries
        $this->pdo->exec("
            CREATE INDEX IF NOT EXISTS idx_session_id ON session_logs(session_id)
        ");
        
        $this->pdo->exec("
            CREATE INDEX IF NOT EXISTS idx_created_at ON session_logs(created_at)
        ");
    }

    /**
     * Persist a log entry to the database
     */
    public function persistLog(array $entry): bool
    {
        $stmt = $this->pdo->prepare("
            INSERT INTO session_logs (session_id, user_id, action, ip, user_agent, fingerprint, meta, created_at, hmac)
            VALUES (:session_id, :user_id, :action, :ip, :user_agent, :fingerprint, :meta, :created_at, :hmac)
        ");
        
        return $stmt->execute([
            ':session_id' => $entry['session_id'] ?? null,
            ':user_id' => $entry['user_id'] ?? null,
            ':action' => $entry['action'] ?? null,
            ':ip' => $entry['ip'] ?? null,
            ':user_agent' => $entry['user_agent'] ?? null,
            ':fingerprint' => $entry['fingerprint'] ?? null,
            ':meta' => json_encode($entry['meta'] ?? []),
            ':created_at' => $entry['created_at'] ?? gmdate('c'),
            ':hmac' => $entry['hmac'] ?? null
        ]);
    }

    /**
     * Query logs with optional filters
     */
    public function queryLogs(array $filters = []): array
    {
        $sql = "SELECT * FROM session_logs";
        $conditions = [];
        $params = [];

        if (!empty($filters['session_id'])) {
            $conditions[] = "session_id = :session_id";
            $params[':session_id'] = $filters['session_id'];
        }

        if (!empty($filters['user_id'])) {
            $conditions[] = "user_id = :user_id";
            $params[':user_id'] = $filters['user_id'];
        }

        if (!empty($filters['action'])) {
            $conditions[] = "action = :action";
            $params[':action'] = $filters['action'];
        }

        if (!empty($conditions)) {
            $sql .= " WHERE " . implode(" AND ", $conditions);
        }

        $sql .= " ORDER BY created_at DESC LIMIT 100";

        $stmt = $this->pdo->prepare($sql);
        $stmt->execute($params);
        
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }

    /**
     * Get the database file path
     */
    public function getDatabasePath(): string
    {
        return $this->dbPath;
    }
}