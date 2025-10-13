<?php
namespace SecureSession;

class AnomalyDetector
{
public function detect(array $sessionContext, ?array $previousContext = null): array
{
    if ($previousContext === null) {
        return ['status' => 'normal'];
    }

    // Compare contexts
    $anomalies = [];

    if ($sessionContext['ip'] !== $previousContext['ip']) {
        $anomalies[] = 'IP address changed';
    }
   if (
    isset($sessionContext['user_agent'], $previousContext['user_agent']) &&
    $sessionContext['user_agent'] !== $previousContext['user_agent']
) {
    $anomalies[] = 'Device/User-Agent changed';
}


    return count($anomalies)
        ? ['status' => 'anomalous', 'details' => $anomalies]
        : ['status' => 'normal'];
}
}
