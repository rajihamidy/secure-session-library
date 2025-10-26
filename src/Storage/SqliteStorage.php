<?php
namespace SecureSession\Storage;

use PDO;
use PDOException;

class SqliteStorage implements StorageInterface
{
    private PDO $pdo;

    public function __construct(string $file = __DIR__ . '/../../data/session_logs.sqlite')
    {
        $dir = dirname($file);

        // ✅ Automatically create the data directory if it doesn’t exist
        if (!is_dir($dir)) {
            mkdir($dir, 0777, true);
        }

        try {
            $this->pdo = new PDO('sqlite:' . $file);
            $this->pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            $this->init();
        } catch (PDOException $e) {
            throw new PDOException("Failed to connect to SQLite database at '$file': " . $e->getMessage());
        }
    }

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
    }

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

    public function queryLogs(array $filters = []): array
    {
        $sql = "SELECT * FROM session_logs ORDER BY created_at DESC LIMIT 100";
        $stmt = $this->pdo->query($sql);
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }
}
