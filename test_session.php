<?php
require 'vendor/autoload.php';
use SecureSession\SecurityConfig;
use SecureSession\SessionManager;
use SecureSession\Logger;
use SecureSession\AnomalyDetector;
use SecureSession\Storage\SqliteStorage;

$storage = new SqliteStorage(__DIR__.'/data/test.sqlite');
$logger = new Logger($storage, 'test_key');
$sm = new SessionManager(new SecurityConfig(), $logger, new AnomalyDetector());

$sm->start();
$_SESSION['foo'] = 'bar';
echo "Old session ID: " . session_id() . "<br>";

$sm->regenerate();
echo "New session ID: " . session_id() . "<br>";

$sm->destroy();
echo "Session destroyed!";
