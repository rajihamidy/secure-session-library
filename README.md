composer require young-programa/secure-session-library

// simple usage
$cfg = new SecureSession\SecurityConfig();
$store = new SecureSession\Storage\SqliteStorage(__DIR__.'/data.sqlite');
$logger = new SecureSession\Logger($store, getenv('SESSION_LOG_HMAC'));
$sm = new SecureSession\SessionManager($cfg, $logger, new SecureSession\AnomalyDetector());
$sm->start();
