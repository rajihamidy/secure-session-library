<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Secure Session Login Demo</title>
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

$config = new SecurityConfig();
$storage = new SqliteStorage(__DIR__ . '/../data/session_logs.sqlite');
$secret = getenv('SESSION_LOG_HMAC') ?: 'change_me_in_env';
$logger = new Logger($storage, $secret);
$anomaly = new AnomalyDetector();

$sm = new SessionManager($config, $logger, $anomaly);
$sm->start(); // start secure session

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
            Session securely regenerated.
        </div>
        <pre class='bg-light p-3 rounded border text-start'>
Old Session ID: {$oldId}
New Session ID: {$newId}
        </pre>";
    } else {
        echo "<script>alert('Invalid login details.');</script>";
    }
}
?>

<?php if ($sm->get('user_id')): ?>
    <!-- Logged-in View -->
    <div class="card shadow-lg border-0 rounded-4 text-center" style="width: 100%; max-width: 420px;">
        <div class="card-body p-4">
            <h3 class="text-success mb-3 fw-bold">Welcome, <?= htmlspecialchars($sm->get('user_id')) ?> 👋</h3>
            <p class="text-muted">You are securely logged in to the session framework.</p>

            <?= $message ?>

            <a href="?logout=true" class="btn btn-danger w-100 fw-semibold mt-3">Logout</a>
        </div>
        <div class="card-footer text-center text-muted small py-2">
            &copy; <?= date('Y'); ?> Secure Session Framework
        </div>
    </div>

<?php else: ?>
    <!-- Login Form View -->
    <div class="card shadow-lg border-0 rounded-4" style="width: 100%; max-width: 400px;">
        <div class="card-body p-4">
            <h3 class="text-center mb-3 text-primary fw-bold">Secure Session Login Demo</h3>
            <p class="text-center text-muted mb-4">Enter your credentials to continue</p>

            <form method="POST" class="needs-validation" novalidate>
                <div class="mb-3">
                    <label for="username" class="form-label fw-semibold">Username</label>
                    <input type="text" class="form-control" id="username" name="username" placeholder="Enter username" autofocus required>
                    <div class="invalid-feedback">Please enter your username.</div>
                </div>

                <div class="mb-3">
                    <label for="password" class="form-label fw-semibold">Password</label>
                    <input type="password" class="form-control" id="password" name="password" placeholder="Enter password" required>
                    <div class="invalid-feedback">Please enter your password.</div>
                </div>

                <button type="submit" class="btn btn-primary w-100 fw-semibold">Login</button>
            </form>
        </div>
        <div class="card-footer text-center text-muted small py-2">
            &copy; <?= date('Y'); ?> Secure Session library
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
