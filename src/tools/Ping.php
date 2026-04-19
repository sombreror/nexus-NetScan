<?php
declare(strict_types=1);

namespace Nexus\Tools;

use Nexus\Middleware\HostValidator;

class Ping
{
    public static function run(string $input): array
    {
        $host = HostValidator::require($input);
        $isIP = filter_var($host, FILTER_VALIDATE_IP) !== false;

        // DNS resolve
        $t0         = microtime(true);
        $resolvedIP = gethostbyname($host);
        $dnsMs      = self::ms($t0);
        $dnsOk      = ($resolvedIP !== $host || $isIP);

        $target = $resolvedIP ?: $host;

        // TCP probes
        [$port80ok,  $port80ms]  = self::tcpProbe($target, 80);
        [$port443ok, $port443ms] = self::tcpProbe($target, 443, true);

        // ICMP-like: try connecting to a port that will refuse (not timeout)
        // Use errno check — ECONNREFUSED (111) means host IS up
        $icmpOk = false;
        $icmpMs = 0.0;
        if (!$port80ok && !$port443ok) {
            [$icmpOk, $icmpMs] = self::refusedProbe($target);
        }

        $reachable = $port80ok || $port443ok || $icmpOk;

        return [
            'host'            => $host,
            'resolved_ip'     => $resolvedIP,
            'dns_resolved'    => $dnsOk,
            'dns_ms'          => $dnsMs,
            'tcp_port80'      => $port80ok,
            'tcp_port80_ms'   => $port80ms,
            'tcp_port443'     => $port443ok,
            'tcp_port443_ms'  => $port443ms,
            'reachable'       => $reachable,
        ];
    }

    private static function tcpProbe(string $addr, int $port, bool $ssl = false): array
    {
        $target = $ssl ? 'ssl://' . $addr : $addr;
        $t = microtime(true);
        $s = @fsockopen($target, $port, $errno, $errstr, (float)SOCKET_TIMEOUT);
        $ms = self::ms($t);
        if ($s) { fclose($s); return [true, $ms]; }
        return [false, $ms];
    }

    /**
     * Probe a typically-refused port.
     * Connection refused (errno 111 or WSAECONNREFUSED 10061) = host is alive.
     * Timeout = host unreachable.
     */
    private static function refusedProbe(string $ip): array
    {
        $t = microtime(true);
        @fsockopen($ip, 7, $errno, $errstr, 1.5);
        $ms = self::ms($t);
        // errno 111 = ECONNREFUSED on Linux, 10061 on Windows
        $alive = in_array($errno, [111, 10061, 61], true);
        return [$alive, $ms];
    }

    private static function ms(float $t0): float
    {
        return round((microtime(true) - $t0) * 1000, 2);
    }
}
