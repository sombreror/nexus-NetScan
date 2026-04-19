<?php
declare(strict_types=1);

namespace Nexus\Tools;

use Nexus\Middleware\HostValidator;

class Dns
{
    private const TYPE_MAP = [
        DNS_A     => 'A',
        DNS_AAAA  => 'AAAA',
        DNS_MX    => 'MX',
        DNS_NS    => 'NS',
        DNS_TXT   => 'TXT',
        DNS_CNAME => 'CNAME',
        DNS_SOA   => 'SOA',
        DNS_PTR   => 'PTR',
        DNS_SRV   => 'SRV',
        DNS_CAA   => 'CAA',
    ];

    public static function run(string $input): array
    {
        $host = HostValidator::sanitize($input);
        if (empty($host)) throw new \InvalidArgumentException('Invalid host.');

        $records = [];
        foreach (self::TYPE_MAP as $type => $name) {
            $res = @dns_get_record($host, $type);
            if (!$res) continue;
            foreach ($res as $r) {
                $value = self::extractValue($name, $r);
                if ($value !== '') {
                    $records[] = ['type' => $name, 'value' => $value, 'ttl' => (int)($r['ttl'] ?? 0)];
                }
            }
        }

        usort($records, fn($a, $b) => strcmp($a['type'], $b['type']));

        return ['host' => $host, 'records' => $records, 'count' => count($records)];
    }

    private static function extractValue(string $type, array $r): string
    {
        return match ($type) {
            'A'     => $r['ip']    ?? '',
            'AAAA'  => $r['ipv6']  ?? '',
            'MX'    => ($r['target'] ?? '') . ' (pri ' . ($r['pri'] ?? '?') . ')',
            'NS'    => $r['target'] ?? '',
            'TXT'   => implode(' ', $r['entries'] ?? [$r['txt'] ?? '']),
            'CNAME' => $r['target'] ?? '',
            'SOA'   => ($r['mname'] ?? '') . ' (serial ' . ($r['serial'] ?? '?') . ')',
            'PTR'   => $r['target'] ?? '',
            'SRV'   => ($r['target'] ?? '') . ':' . ($r['port'] ?? '?') . ' pri=' . ($r['pri'] ?? '?'),
            'CAA'   => ($r['flags'] ?? '') . ' ' . ($r['tag'] ?? '') . ' ' . ($r['value'] ?? ''),
            default => $r['target'] ?? $r['ip'] ?? '',
        };
    }
}
