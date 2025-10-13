<?php
namespace SecureSession;

class AnomalyDetector
{
    public function detect(array $sessionContext, array $previousContext = null): array
    {
        $anomalies = [];
        if ($previousContext) {
            if (isset($sessionContext['ip'], $previousContext['ip']) && $sessionContext['ip'] !== $previousContext['ip']) {
                $anomalies[] = 'ip_change';
            }
            if (isset($sessionContext['fingerprint'], $previousContext['fingerprint']) &&
                $sessionContext['fingerprint'] !== $previousContext['fingerprint']) {
                $anomalies[] = 'fingerprint_mismatch';
            }
        }
        return $anomalies;
    }
}
