<?php
namespace SecureSession\Storage;

interface StorageInterface
{
    public function persistLog(array $entry): bool;
    public function queryLogs(array $filters = []): array;
}
