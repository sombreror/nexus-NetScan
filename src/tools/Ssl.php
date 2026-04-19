<?php
declare(strict_types=1);

namespace Nexus\Tools;

use Nexus\Middleware\HostValidator;

class Ssl
{
    public static function run(string $input): array
    {
        $host = HostValidator::require($input);

        $ctx = stream_context_create(['ssl' => [
            'capture_peer_cert'       => true,
            'capture_peer_cert_chain' => true,
            'verify_peer'             => true,
            'verify_peer_name'        => true,
            'SNI_enabled'             => true,
        ]]);

        $t0   = microtime(true);
        $sock = @stream_socket_client(
            "ssl://{$host}:443", $errno, $errstr,
            (float)CURL_CONNECT_TIMEOUT, STREAM_CLIENT_CONNECT, $ctx
        );
        $ms = round((microtime(true) - $t0) * 1000, 2);

        if (!$sock) {
            return ['host' => $host, 'valid' => false,
                    'error' => $errstr ?: "Connection failed (errno $errno)",
                    'handshake_ms' => $ms];
        }

        $params = stream_context_get_params($sock);
        fclose($sock);

        $cert = @openssl_x509_parse($params['options']['ssl']['peer_certificate'] ?? '');
        if (!$cert) {
            return ['host' => $host, 'valid' => false,
                    'error' => 'Could not parse certificate', 'handshake_ms' => $ms];
        }

        $notAfterTs  = (int)($cert['validTo_time_t']   ?? 0);
        $notBeforeTs = (int)($cert['validFrom_time_t'] ?? 0);
        $daysLeft    = (int)(($notAfterTs - time()) / 86400);

        $san      = $cert['extensions']['subjectAltName'] ?? '';
        $altNames = [];
        if ($san) { preg_match_all('/DNS:([^\s,]+)/', $san, $m); $altNames = $m[1] ?? []; }

        $chain = $params['options']['ssl']['peer_certificate_chain'] ?? [];

        return [
            'host'         => $host,
            'valid'        => true,
            'subject'      => $cert['subject']['CN']  ?? '',
            'issuer'       => $cert['issuer']['O']    ?? '',
            'issuer_cn'    => $cert['issuer']['CN']   ?? '',
            'not_before'   => date('Y-m-d', $notBeforeTs),
            'not_after'    => date('Y-m-d', $notAfterTs),
            'days_left'    => $daysLeft,
            'expiring'     => $daysLeft < 30,
            'expired'      => $daysLeft < 0,
            'alt_names'    => $altNames,
            'chain_depth'  => count($chain),
            'serial'       => strtoupper($cert['serialNumberHex'] ?? ''),
            'handshake_ms' => $ms,
        ];
    }
}
