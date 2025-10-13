<?php
use PHPUnit\Framework\TestCase;
use SecureSession\SecurityConfig;
use SecureSession\Logger;
use SecureSession\SessionManager;
use SecureSession\AnomalyDetector;
use SecureSession\Storage\SqliteStorage;

class SessionManagerTest extends TestCase
{
    /** @var SessionManager */
    protected $sm;

    protected function setUp(): void
    {
        if (session_status() === PHP_SESSION_ACTIVE) {
            session_destroy();
        }
        @mkdir(__DIR__ . '/../data');
        $storage = new \SecureSession\Storage\SqliteStorage(__DIR__ . '/../data/test.sqlite');
        $logger = new \SecureSession\Logger($storage, 'test_key');
        $this->sm = new SessionManager(new SecurityConfig(), $logger, new AnomalyDetector());
    }

    public function testStartAndRegenerate()
    {
        $this->sm->start();
        $_SESSION['foo'] = 'bar';
        $old = session_id();
        $this->sm->regenerate();
        $this->assertNotEquals($old, session_id());
        $this->assertEquals('bar', $_SESSION['foo']);
        $this->sm->destroy();
    }
}
