<?php
/**
 * CSRF Protection Demo
 * Shows how to protect forms and AJAX requests from CSRF attacks
 */

require __DIR__ . '/../vendor/autoload.php';

use SecureSession\SecurityConfig;
use SecureSession\Logger;
use SecureSession\SessionManager;
use SecureSession\AnomalyDetector;
use SecureSession\Storage\SqliteStorage;
use SecureSession\CsrfProtection;

// Initialize session
$config = new SecurityConfig();
$storage = new SqliteStorage();
$logger = new Logger($storage, 'secret-key');
$sm = new SessionManager($config, $logger, new AnomalyDetector());
$sm->start();

// Initialize CSRF protection
$csrf = new CsrfProtection($sm);

$message = '';
$error = '';

// Handle form submission with CSRF protection
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    
    // VALIDATE CSRF TOKEN - THIS IS THE KEY PROTECTION
    if (!$csrf->validateRequest()) {
        // CSRF validation failed - log and reject
        $error = '🚫 CSRF validation failed! Request rejected.';
        $csrf->handleFailure(false); // Don't terminate, just log
    } else {
        // CSRF token is valid - process the request
        $action = $_POST['action'] ?? '';
        
        switch ($action) {
            case 'transfer':
                $amount = $_POST['amount'] ?? 0;
                $to = $_POST['to'] ?? '';
                $message = "✅ Transfer successful! Sent $$amount to $to";
                break;
                
            case 'delete':
                $itemId = $_POST['item_id'] ?? '';
                $message = "✅ Item #$itemId deleted successfully!";
                break;
                
            case 'update_settings':
                $email = $_POST['email'] ?? '';
                $message = "✅ Settings updated! Email: $email";
                break;
                
            default:
                $error = '❌ Unknown action';
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CSRF Protection Demo</title>
    <?= $csrf->getMetaTag() ?> <!-- For AJAX requests -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body class="bg-light">
    <div class="container mt-5">
        <div class="row">
            <div class="col-md-8 offset-md-2">
                
                <!-- Header -->
                <div class="alert alert-info">
                    <h4>🛡️ CSRF Protection Demo</h4>
                    <p class="mb-0">All forms are protected with CSRF tokens. Try submitting without the token to see it fail!</p>
                </div>

                <?php if ($message): ?>
                <div class="alert alert-success"><?= $message ?></div>
                <?php endif; ?>

                <?php if ($error): ?>
                <div class="alert alert-danger"><?= $error ?></div>
                <?php endif; ?>

                <!-- Example 1: Bank Transfer Form -->
                <div class="card mb-3">
                    <div class="card-header bg-primary text-white">
                        <h5 class="mb-0">💰 Bank Transfer (Protected)</h5>
                    </div>
                    <div class="card-body">
                        <form method="POST">
                            <?= $csrf->getHiddenInput() ?> <!-- CSRF Protection -->
                            <input type="hidden" name="action" value="transfer">
                            
                            <div class="mb-3">
                                <label class="form-label">Transfer To:</label>
                                <input type="text" name="to" class="form-control" value="user@example.com" required>
                            </div>
                            
                            <div class="mb-3">
                                <label class="form-label">Amount ($):</label>
                                <input type="number" name="amount" class="form-control" value="100" required>
                            </div>
                            
                            <button type="submit" class="btn btn-primary">Transfer Money</button>
                        </form>
                    </div>
                </div>

                <!-- Example 2: Delete Action -->
                <div class="card mb-3">
                    <div class="card-header bg-danger text-white">
                        <h5 class="mb-0">🗑️ Delete Item (Protected)</h5>
                    </div>
                    <div class="card-body">
                        <form method="POST">
                            <?= $csrf->getHiddenInput() ?>
                            <input type="hidden" name="action" value="delete">
                            <input type="hidden" name="item_id" value="12345">
                            
                            <p>Are you sure you want to delete item #12345?</p>
                            <button type="submit" class="btn btn-danger">Delete Item</button>
                        </form>
                    </div>
                </div>

                <!-- Example 3: AJAX Request -->
                <div class="card mb-3">
                    <div class="card-header bg-success text-white">
                        <h5 class="mb-0">⚡ AJAX Request (Protected)</h5>
                    </div>
                    <div class="card-body">
                        <button id="ajaxBtn" class="btn btn-success">Send Protected AJAX Request</button>
                        <div id="ajaxResult" class="mt-3"></div>
                    </div>
                </div>

                <!-- Testing Section -->
                <div class="card mb-3">
                    <div class="card-header bg-warning">
                        <h5 class="mb-0">🧪 Test CSRF Attack</h5>
                    </div>
                    <div class="card-body">
                        <p><strong>Try this attack:</strong></p>
                        <ol>
                            <li>Open developer console (F12)</li>
                            <li>Remove the CSRF token from a form using: 
                                <code>document.querySelector('input[name="csrf_token"]').remove()</code>
                            </li>
                            <li>Submit the form - it will be rejected! ✅</li>
                        </ol>
                        
                        <hr>
                        
                        <p><strong>Simulate external attack:</strong></p>
                        <textarea class="form-control mb-2" rows="5" readonly><?= htmlspecialchars('
<!-- Attacker\'s page at evil.com -->
<form action="http://yoursite.com/csrf_demo.php" method="POST">
    <input type="hidden" name="action" value="transfer">
    <input type="hidden" name="to" value="attacker@evil.com">
    <input type="hidden" name="amount" value="10000">
    <!-- NO CSRF TOKEN - This will fail! -->
</form>
<script>document.forms[0].submit();</script>
') ?></textarea>
                        <small class="text-muted">This attack will fail because the CSRF token is missing!</small>
                    </div>
                </div>

                <!-- Current Token Info -->
                <div class="card">
                    <div class="card-header">
                        <h5 class="mb-0">🔑 Current CSRF Token</h5>
                    </div>
                    <div class="card-body">
                        <p><strong>Token:</strong> <code><?= htmlspecialchars($csrf->getToken()) ?></code></p>
                        <small class="text-muted">
                            This token is unique per session and must be included in all state-changing requests.
                            It's automatically regenerated when the session is regenerated.
                        </small>
                    </div>
                </div>

            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // AJAX example with CSRF protection
        document.getElementById('ajaxBtn').addEventListener('click', function() {
            const resultDiv = document.getElementById('ajaxResult');
            resultDiv.innerHTML = '<div class="spinner-border spinner-border-sm"></div> Sending...';
            
            // Get CSRF token from meta tag
            const token = document.querySelector('meta[name="csrf-token"]').getAttribute('content');
            
            fetch(window.location.href, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'X-CSRF-Token': token // Send token in header
                },
                body: 'action=update_settings&email=ajax@example.com'
            })
            .then(response => response.text())
            .then(html => {
                // Extract success message from response
                if (html.includes('Settings updated')) {
                    resultDiv.innerHTML = '<div class="alert alert-success">✅ AJAX request successful!</div>';
                } else {
                    resultDiv.innerHTML = '<div class="alert alert-danger">❌ AJAX request failed!</div>';
                }
            })
            .catch(error => {
                resultDiv.innerHTML = '<div class="alert alert-danger">Error: ' + error + '</div>';
            });
        });
    </script>
</body>
</html>