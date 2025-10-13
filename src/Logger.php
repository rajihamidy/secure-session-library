<?php
namespace SecureSession;

use SecureSession\Storage\StorageInterface;

class Logger
{
    private StorageInterface $storage;
    private string $secretKey;

    public function __construct(StorageInterface $storage, string $secretKey)
    {
        $this->storage = $storage;
        $this->secretKey = $secretKey;
    }

    public function write(array $data): bool
    {
        $data['created_at'] = $data['created_at'] ?? gmdate('c');
        $payload = json_encode($data, JSON_UNESCAPED_SLASHES);
        $data['hmac'] = hash_hmac('sha256', $payload, $this->secretKey);
        return $this->storage->persistLog($data);
    }
}
