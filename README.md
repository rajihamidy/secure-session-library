# Secure Session Library - Examples

## 🚀 Zero Configuration Setup

The library automatically handles everything:
- ✅ Creates database in writable location
- ✅ Sets up tables and indexes
- ✅ Manages session lifecycle
- ✅ No manual directory creation needed!

## Quick Start

### 1. Install via Composer
```bash
composer require your-vendor/secure-session-library
```

### 2. Copy the Example
```bash
cp vendor/your-vendor/secure-session-library/examples/index.php ./
```

### 3. Run It
```bash
php -S localhost:8000
```

That's it! Visit http://localhost:8000/index.php

## Minimal Code Example

```php
<?php
require 'vendor/autoload.php';

use SecureSession\{SecurityConfig, Logger, SessionManager, AnomalyDetector};
use SecureSession\Storage\SqliteStorage;

// Zero configuration - everything is automatic!
$config = new SecurityConfig();
$storage = new SqliteStorage(); // Auto-creates DB
$logger = new Logger($storage, 'your-secret-key');
$sm = new SessionManager($config, $logger, new AnomalyDetector());

$sm->start(); // Done!
```

## Database Location

The library automatically chooses the best writable location:

1. **System temp directory** (most compatible): `/tmp/secure-session-library/session_logs.sqlite`
2. **Current working directory**: `./data/session_logs.sqlite`
3. **Library directory** (development): `vendor/.../data/session_logs.sqlite`

You can also specify a custom path:
```php
$storage = new SqliteStorage('/var/www/myapp/logs/sessions.sqlite');
```

## Demo Credentials
- **Username:** demo
- **Password:** password

## What to Test

### Auto-Logout Feature
1. Login with the demo credentials
2. Wait for the configured idle timeout (default: 300 seconds / 5 minutes)
3. Refresh the page - you'll be automatically logged out

**To test faster:** Modify the timeout in `index.php`:
```php
$config->idleTimeout = 30; // 30 seconds for testing
```

### Session Regeneration
- After successful login, the session ID is automatically regenerated
- Check the "Session Information" box to see the new session ID

### Forensic Logging
- All session actions are logged to SQLite database
- View recent logs at the bottom of the page
- Logged actions include: create, regenerate, destroy, timeout, anomaly

### Anomaly Detection
- Try accessing from different browsers/IPs
- The system detects suspicious changes in session context

## File Structure

```
examples/
├── index.php          # Main demo page
├── data/              # Auto-created for SQLite logs
│   └── session_logs.sqlite
└── README.md          # This file
```

## Configuration Options

Edit `index.php` to customize:

```php
$config->idleTimeout = 300;      // Session timeout in seconds
$config->absoluteTimeout = 86400; // Max session lifetime (optional)
$config->secureCookie = true;    // Require HTTPS (production)
$config->httpOnly = true;        // Prevent JavaScript access
$config->sameSite = 'Lax';       // CSRF protection
```

## Database Location

By default, logs are stored in:
- Development: `examples/data/session_logs.sqlite`
- Production: Configure to use your app's writable directory

## Troubleshooting

### "No logs being saved"
1. Check that the `data` folder exists and is writable
2. Verify PHP has permission to create SQLite files
3. Check error logs: `tail -f /var/log/apache2/error.log`

### "Session not expiring"
1. Verify `idleTimeout` is set to a low value for testing
2. Check that `$sm->start()` is called on every page
3. Clear browser cookies and try again

### "Permission denied"
```bash
chmod 755 examples/data
chmod 644 examples/data/session_logs.sqlite
```

## Production Deployment

When deploying to production:

1. **Change the HMAC secret:**
   ```php
   $secret = getenv('SESSION_LOG_HMAC'); // Use environment variable
   ```

2. **Enable secure cookies:**
   ```php
   $config->secureCookie = true; // Requires HTTPS
   ```

3. **Use a writable directory:**
   ```php
   $dbPath = '/var/www/writable/session_logs.sqlite';
   ```

4. **Set proper file permissions:**
   ```bash
   chmod 755 /var/www/writable
   chmod 644 /var/www/writable/session_logs.sqlite
   ```

## Support

For issues or questions, please visit:
https://github.com/rajihamidy/secure-session-library or rajihamidu90@gmail.com