<?php
declare(strict_types=1);

namespace Nexus\Db;

class Logger
{
    public static function write(
        string $tool,
        string $target,
        string $level,
        mixed  $result,
        int    $durationMs,
        ?int   $userId = null
    ): void {
        try {
            $encoded = is_string($result) ? $result : json_encode($result, JSON_UNESCAPED_UNICODE);
            Database::execute(
                'INSERT INTO logs (level, tool, target, ip, user_id, result, duration_ms)
                 VALUES (?, ?, ?, ?, ?, ?, ?)',
                [$level, $tool, $target, self::clientIP(), $userId, $encoded, $durationMs]
            );
        } catch (\Throwable) {}
    }

    public static function clientIP(): string
    {
        foreach (['HTTP_CF_CONNECTING_IP', 'HTTP_X_FORWARDED_FOR', 'REMOTE_ADDR'] as $k) {
            if (!empty($_SERVER[$k])) {
                $ip = trim(explode(',', $_SERVER[$k])[0]);
                if (filter_var($ip, FILTER_VALIDATE_IP)) return $ip;
            }
        }
        return '0.0.0.0';
    }
}
