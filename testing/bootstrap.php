<?php
// Bootstrap for PHPUnit session tests
if (session_status() === PHP_SESSION_ACTIVE) {
    session_write_close();
}

// Create isolated session path before test starts
$sessionPath = __DIR__ . '/../data/sessions';
@mkdir($sessionPath, 0777, true);

// Configure PHP session for CLI testing (before any test output)
ini_set('session.save_handler', 'files');
ini_set('session.save_path', $sessionPath);
ini_set('session.use_cookies', '0');
ini_set('session.use_only_cookies', '0');
ini_set('session.use_trans_sid', '0');

// Ensure output buffering started to prevent header warnings
if (ob_get_level() === 0) ob_start();
