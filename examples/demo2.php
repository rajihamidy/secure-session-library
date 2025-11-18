<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Demo Interface for Secure Session Library Implementation</title>
    <!-- Bootstrap 5 CDN -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body class="bg-light d-flex align-items-center justify-content-center vh-100">

<?php
require __DIR__ . '/../vendor/autoload.php';

use SecureSession\SecurityConfig;
use SecureSession\Logger;
use SecureSession\SessionManager;
use SecureSession\AnomalyDetector;
use SecureSession\Storage\SqliteStorage;
use SecureSession\CsrfProtection;

$config = new SecurityConfig();

// Optional: Customize timeout (defaults to 300 seconds / 5 minutes)
// $config->idleTimeout = 30; // 30 seconds for testing

// Zero configuration - database location is automatic!
$storage = new SqliteStorage(); // Auto-creates database in best writable location
$secret = getenv('SESSION_LOG_HMAC') ?: 'change_me_in_env';
$logger = new Logger($storage, $secret);
$anomaly = new AnomalyDetector();

$sm = new SessionManager($config, $logger, $anomaly);

// Check if session cookie exists (user was previously here)
$hadSessionCookie = isset($_COOKIE[session_name()]);

$sm->start(); // Start session - auto-logout happens here if idle timeout exceeded

// Initialize CSRF protection
$csrf = new CsrfProtection($sm);

// Detect if session timed out
$sessionExpired = $hadSessionCookie && !$sm->get('user_id') && empty($_SESSION);

// --- Logout functionality ---
if (isset($_GET['logout'])) {
    $sm->destroy();
    header("Location: " . $_SERVER['PHP_SELF']);
    exit;
}

// --- Login process ---
$message = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = trim($_POST['username'] ?? '');
    $password = trim($_POST['password'] ?? '');

    if ($username === 'test' && $password === 'pass') {
        $sm->set('user_id', $username);

        $oldId = session_id();
        $sm->regenerate();
        $newId = session_id();

        $message = "
        <div class='alert alert-success text-center'>
            <strong>✅ Login successful!</strong><br>
            Session securely regenerated and logged.
        </div>
        ";
    } else {
        $message = "<div class='alert alert-danger'>❌ Invalid credentials. Try again.</div>";
    }
}
?>

<?php if ($sm->get('user_id')): ?>
    <!-- Logged-in View -->
    <div class="card shadow-lg border-0 rounded-4 text-center" style="width: 100%; max-width: 420px;">
        <div class="card-body p-4">
            <h3 class="text-success mb-3 fw-bold">Welcome, <?= htmlspecialchars($sm->get('user_id')) ?> 👋</h3>
            <p class="text-muted">You are securely logged in.</p>

            <?= $message ?>

            <div class="alert alert-info mt-3 small">
                <strong>ℹ️ Auto-Logout Info:</strong><br>
                Your session will automatically expire after <strong><?= $config->idleTimeout ?> seconds</strong> (<?= round($config->idleTimeout/60, 1) ?> minutes) of inactivity.<br>
                <small class="text-muted">Simply refresh or navigate to any page to extend your session.</small><br>
                <small class="text-muted mt-1 d-block">Database: <code><?= basename($storage->getDatabasePath()) ?></code></small>
            </div>

            <a href="?logout=true" class="btn btn-danger w-100 fw-semibold mt-2">Logout</a>
        </div>
        <div class="card-footer text-center text-muted small py-2">
            &copy; <?= date('Y'); ?> Secure Session Framework
        </div>
    </div>

<?php else: ?>
    <!-- Login Form View -->
    <div class="card shadow-lg border-0 rounded-4" style="width: 100%; max-width: 500px;">
        <div class="card-body p-4">
            <h3 class="text-center mb-3 text-primary fw-bold">Demo Interface for Secure Session Library</h3>
            <p class="text-center text-muted mb-4">Enter your credentials to continue</p>

            <?php if ($sessionExpired): ?>
            <div class="alert alert-warning">
                <strong>⚠️ Session Expired</strong><br>
                Your session was terminated due to <?= $config->idleTimeout ?> seconds of inactivity.
            </div>
            <?php endif; ?>

            <?= $message ?>

            <form method="POST" class="needs-validation" novalidate>
                <div class="mb-3">
                    <label for="username" class="form-label fw-semibold">Username</label>
                    <input type="text" class="form-control" id="username" name="username" placeholder="Enter username" value="test" autofocus required>
                    <div class="invalid-feedback">Please enter your username.</div>
                </div>

                <div class="mb-3">
                    <label for="password" class="form-label fw-semibold">Password</label>
                    <input type="password" class="form-control" id="password" name="password" placeholder="Enter password" value="pass" required>
                    <div class="invalid-feedback">Please enter your password.</div>
                </div>

                <button type="submit" class="btn btn-primary w-100 fw-semibold">Login</button>
            </form>
            
            <div class="alert alert-secondary mt-3 small">
                <strong>🔐 Demo Credentials:</strong><br>
                Username: <code>test</code> | Password: <code>pass</code><br>
                <hr class="my-2">
                <strong>⏱️ Session Timeout:</strong> <?= $config->idleTimeout ?> seconds (<?= round($config->idleTimeout/60, 1) ?> min)<br>
                <small class="text-muted">Leave the page idle to test auto-logout</small>
            </div>
        </div>
        <div class="card-footer text-center text-muted small py-2">
            &copy; <?= date('Y'); ?> Secure Session Library
        </div>
    </div>
<?php endif; ?>

<script>
    // Bootstrap form validation
    (() => {
        'use strict';
        const forms = document.querySelectorAll('.needs-validation');
        Array.from(forms).forEach(form => {
            form.addEventListener('submit', event => {
                if (!form.checkValidity()) {
                    event.preventDefault();
                    event.stopPropagation();
                }
                form.classList.add('was-validated');
            }, false);
        });
    })();
</script>

<!-- Bootstrap JS Bundle -->
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>