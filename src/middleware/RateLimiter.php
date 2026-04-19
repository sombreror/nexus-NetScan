<?php
declare(strict_types=1);

namespace Nexus\Middleware;

use Nexus\Db\{Database, Logger};

class RateLimiter
{
    public static function check(): void
    {
        $ip  = Logger::clientIP();
        $now = time();

        try {
            $db   = Database::get();
            $stmt = $db->prepare('SELECT requests, window_start FROM rate_limits WHERE ip = ?');
            $stmt->execute([$ip]);
            $row = $stmt->fetch();

            if (!$row) {
                $db->prepare('INSERT INTO rate_limits (ip,requests,window_start) VALUES (?,1,?)')
                   ->execute([$ip, date('Y-m-d H:i:s', $now)]);
                return;
            }

            $windowStart = strtotime($row['window_start']);

            if ($now - $windowStart > RATE_WINDOW) {
                $db->prepare('UPDATE rate_limits SET requests=1,window_start=? WHERE ip=?')
                   ->execute([date('Y-m-d H:i:s', $now), $ip]);
                return;
            }

            if ((int)$row['requests'] >= RATE_LIMIT) {
                $retryAfter = RATE_WINDOW - ($now - $windowStart);
                http_response_code(429);
                header('Retry-After: ' . $retryAfter);
                echo json_encode([
                    'ok'          => false,
                    'error'       => 'Rate limit exceeded.',
                    'retry_after' => $retryAfter,
                ]);
                exit;
            }

            $db->prepare('UPDATE rate_limits SET requests=requests+1 WHERE ip=?')->execute([$ip]);

        } catch (\Throwable) {
            // DB down — allow request
        }
    }
}
