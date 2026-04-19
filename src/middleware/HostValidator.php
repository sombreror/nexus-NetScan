<?php
declare(strict_types=1);

namespace Nexus\Middleware;

class HostValidator
{
    /**
     * Strip protocol, path, query, port — return lowercase hostname.
     * No whitelist. Any valid hostname/IP accepted.
     */
    public static function sanitize(string $input): string
    {
        $input = strtolower(trim($input));
        // Strip protocol
        $input = preg_replace('#^[a-z]+://#i', '', $input);
        // Strip path, query, fragment
        $input = explode('/', $input)[0];
        $input = explode('?', $input)[0];
        $input = explode('#', $input)[0];
        // Strip port (but keep IPv6 intact)
        if (!str_starts_with($input, '[')) {
            $input = preg_replace('/:\d+$/', '', $input);
        }
        // Allow only valid hostname chars
        $input = preg_replace('/[^a-z0-9.\-:\[\]]/', '', $input);
        return $input;
    }

    /**
     * Sanitize and validate — throws if empty or looks like localhost/private meta.
     */
    public static function require(string $input): string
    {
        $host = self::sanitize($input);

        if (empty($host)) {
            throw new \InvalidArgumentException('Empty or invalid host.');
        }

        // Block localhost / loopback names (server self-protection)
        $blocked = ['localhost', '::1', '0.0.0.0'];
        if (in_array($host, $blocked, true)) {
            throw new \InvalidArgumentException('Host not allowed.');
        }

        // Block 127.x.x.x
        if (preg_match('/^127\./', $host)) {
            throw new \InvalidArgumentException('Loopback address not allowed.');
        }

        return $host;
    }
}
