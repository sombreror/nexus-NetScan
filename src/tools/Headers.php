<?php
declare(strict_types=1);

namespace Nexus\Tools;

use Nexus\Middleware\HostValidator;

class Headers
{
    private const SECURITY_CHECKS = [
        'hsts'        => 'strict-transport-security',
        'csp'         => 'content-security-policy',
        'x-frame'     => 'x-frame-options',
        'x-xss'       => 'x-xss-protection',
        'nosniff'     => 'x-content-type-options',
        'referrer'    => 'referrer-policy',
        'permissions' => 'permissions-policy',
        'coep'        => 'cross-origin-embedder-policy',
    ];

    public static function run(string $input): array
    {
        $host = HostValidator::require($input);
        $url  = 'https://' . $host;

        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HEADER         => true,
            CURLOPT_NOBODY         => true,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_MAXREDIRS      => CURL_MAX_REDIRECTS,
            CURLOPT_TIMEOUT        => CURL_TIMEOUT,
            CURLOPT_CONNECTTIMEOUT => CURL_CONNECT_TIMEOUT,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_USERAGENT      => CURL_USER_AGENT,
        ]);

        $t0       = microtime(true);
        $raw      = curl_exec($ch);
        $ms       = round((microtime(true) - $t0) * 1000, 2);
        $code     = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $err      = curl_error($ch);
        $finalUrl = curl_getinfo($ch, CURLINFO_EFFECTIVE_URL);
        curl_close($ch);

        $headers  = self::parseHeaders((string)$raw);
        $security = [];
        foreach (self::SECURITY_CHECKS as $key => $header) {
            $security[$key] = isset($headers[$header]);
        }

        return [
            'host'        => $host,
            'url'         => $url,
            'final_url'   => $finalUrl,
            'status_code' => $code,
            'latency_ms'  => $ms,
            'security'    => $security,
            'sec_score'   => count(array_filter($security)),
            'sec_max'     => count(self::SECURITY_CHECKS),
            'headers'     => $headers,
            'error'       => $err ?: null,
        ];
    }

    private static function parseHeaders(string $raw): array
    {
        $out = [];
        foreach (explode("\n", $raw) as $line) {
            $line = trim($line);
            if (str_contains($line, ':')) {
                [$k, $v] = explode(':', $line, 2);
                $out[strtolower(trim($k))] = trim($v);
            }
        }
        return $out;
    }
}
