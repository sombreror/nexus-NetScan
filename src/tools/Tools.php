<?php
declare(strict_types=1);

namespace Nexus\Tools;

use Nexus\Middleware\HostValidator;

// ─── TRACEROUTE ───────────────────────────────────────────────────────────────
class Traceroute
{
    public static function run(string $input): array
    {
        $host   = HostValidator::require($input);
        $destIP = gethostbyname($host);
        $isIP   = filter_var($host, FILTER_VALIDATE_IP) !== false;

        if ($destIP === $host && !$isIP) {
            return ['host' => $host, 'hops' => [], 'total_hops' => 0,
                    'error' => 'DNS resolution failed', 'destination_ip' => null];
        }

        $hops  = [];
        $ports = [80, 443, 53];

        for ($ttl = 1; $ttl <= TRACEROUTE_MAX_HOPS; $ttl++) {
            $bestMs  = null;
            $reached = false;

            foreach ($ports as $port) {
                $t0   = microtime(true);
                $sock = @fsockopen($destIP, $port, $errno, $errstr, 1.5);
                $ms   = round((microtime(true) - $t0) * 1000, 2);
                if ($sock) { fclose($sock); $bestMs = $ms; $reached = true; break; }
                if ($bestMs === null || $ms < $bestMs) $bestMs = $ms;
            }

            $hops[] = [
                'hop'    => $ttl,
                'ip'     => ($reached || $ttl === TRACEROUTE_MAX_HOPS) ? $destIP : '* * *',
                'rtt_ms' => $bestMs ?? 0,
                'status' => $reached ? 'reached' : 'transit',
            ];
            if ($reached) break;
        }

        return ['host' => $host, 'destination_ip' => $destIP,
                'hops' => $hops, 'total_hops' => count($hops)];
    }
}

// ─── WHOIS ────────────────────────────────────────────────────────────────────
class Whois
{
    private const SERVERS = [
        'com' => 'whois.verisign-grs.com', 'net' => 'whois.verisign-grs.com',
        'org' => 'whois.pir.org',          'io'  => 'whois.nic.io',
        'co'  => 'whois.nic.co',           'ai'  => 'whois.nic.ai',
        'dev' => 'whois.nic.google',       'app' => 'whois.nic.google',
        'uk'  => 'whois.nic.uk',           'de'  => 'whois.denic.de',
        'fr'  => 'whois.nic.fr',           'it'  => 'whois.nic.it',
        'nl'  => 'whois.domain-registry.nl','eu'  => 'whois.eu',
    ];

    public static function run(string $input): array
    {
        $host   = HostValidator::require($input);
        $parts  = explode('.', $host);
        $tld    = array_pop($parts);
        $sld    = array_pop($parts);
        $domain = "$sld.$tld";
        $server = self::SERVERS[$tld] ?? 'whois.iana.org';

        $raw  = '';
        $sock = @fsockopen($server, 43, $errno, $errstr, 5);
        if ($sock) {
            fwrite($sock, "$domain\r\n");
            $sock && stream_set_timeout($sock, 5);
            while (!feof($sock)) $raw .= fgets($sock, 256);
            fclose($sock);
        }

        return [
            'domain'  => $domain,
            'host'    => $host,
            'server'  => $server,
            'data'    => self::parse($raw),
            'raw_len' => strlen($raw),
            'found'   => !empty(self::parse($raw)),
        ];
    }

    private static function parse(string $raw): array
    {
        $patterns = [
            'registrar'   => '/Registrar:\s*(.+)/i',
            'created'     => '/Creation Date:\s*(.+)/i',
            'expires'     => '/Registry Expiry Date:\s*(.+)/i',
            'updated'     => '/Updated Date:\s*(.+)/i',
            'status'      => '/Domain Status:\s*(.+)/i',
            'nameservers' => '/Name Server:\s*(.+)/i',
            'registrant'  => '/Registrant Organization:\s*(.+)/i',
            'dnssec'      => '/DNSSEC:\s*(.+)/i',
        ];
        $out = [];
        foreach ($patterns as $key => $pat) {
            if (preg_match_all($pat, $raw, $m)) {
                $vals = array_values(array_unique(array_map('trim', $m[1])));
                $out[$key] = count($vals) === 1 ? $vals[0] : $vals;
            }
        }
        return $out;
    }
}

// ─── UPTIME ───────────────────────────────────────────────────────────────────
class Uptime
{
    private const PORTS = [80 => 'HTTP', 443 => 'HTTPS', 53 => 'DNS', 22 => 'SSH'];

    public static function run(string $input): array
    {
        $host   = HostValidator::require($input);
        $checks = [];

        foreach (self::PORTS as $port => $label) {
            $t0   = microtime(true);
            $sock = @fsockopen($host, $port, $errno, $errstr, (float)SOCKET_TIMEOUT);
            $ms   = round((microtime(true) - $t0) * 1000, 2);
            $up   = $sock !== false;
            if ($sock) fclose($sock);
            $checks[] = ['port' => $port, 'service' => $label, 'up' => $up, 'ms' => $ms];
        }

        $upCount = count(array_filter($checks, fn($c) => $c['up']));
        return ['host' => $host, 'checks' => $checks, 'up' => $upCount > 0,
                'score' => round($upCount / count($checks) * 100)];
    }
}

// ─── LATENCY ──────────────────────────────────────────────────────────────────
class Latency
{
    public static function run(string $input): array
    {
        $host    = HostValidator::require($input);
        $samples = [];

        for ($i = 0; $i < LATENCY_ROUNDS; $i++) {
            $t0   = microtime(true);
            $sock = @fsockopen($host, 443, $errno, $errstr, (float)SOCKET_TIMEOUT);
            $ms   = round((microtime(true) - $t0) * 1000, 2);
            if ($sock) fclose($sock);
            $samples[] = $ms;
            if ($i < LATENCY_ROUNDS - 1) usleep(LATENCY_SLEEP_US);
        }

        $min      = min($samples);
        $max      = max($samples);
        $avg      = round(array_sum($samples) / count($samples), 2);
        $variance = array_sum(array_map(fn($x) => ($x - $avg) ** 2, $samples)) / count($samples);
        $jitter   = round(sqrt($variance), 2);
        $sorted   = $samples; sort($sorted);
        $p95      = (float)$sorted[(int)ceil(0.95 * count($sorted)) - 1];
        $grade    = $avg < 50 ? 'EXCELLENT' : ($avg < 150 ? 'GOOD' : ($avg < 300 ? 'FAIR' : 'POOR'));

        return ['host' => $host, 'samples' => $samples, 'min_ms' => $min, 'avg_ms' => $avg,
                'max_ms' => $max, 'p95_ms' => $p95, 'jitter' => $jitter,
                'grade' => $grade, 'rounds' => LATENCY_ROUNDS];
    }
}

// ─── IP INFO ──────────────────────────────────────────────────────────────────
class IpInfo
{
    public static function run(string $input): array
    {
        $host = HostValidator::require($input);
        $ip   = filter_var($host, FILTER_VALIDATE_IP) ? $host : gethostbyname($host);

        if ($ip === $host && !filter_var($host, FILTER_VALIDATE_IP)) {
            throw new \RuntimeException('DNS resolution failed.');
        }

        $isPrivate = filter_var($ip, FILTER_VALIDATE_IP,
            FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false;

        $info = [];
        if (!$isPrivate) {
            $ch = curl_init("https://ipinfo.io/$ip/json");
            curl_setopt_array($ch, [
                CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 5,
                CURLOPT_USERAGENT => CURL_USER_AGENT,
            ]);
            $body = curl_exec($ch);
            $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);
            if ($code === 200 && $body) $info = json_decode($body, true) ?? [];
        }

        return array_filter([
            'host'       => $host,
            'ip'         => $ip,
            'is_private' => $isPrivate,
            'hostname'   => $info['hostname'] ?? null,
            'city'       => $info['city']     ?? null,
            'region'     => $info['region']   ?? null,
            'country'    => $info['country']  ?? null,
            'org'        => $info['org']       ?? null,
            'asn'        => isset($info['org']) ? explode(' ', $info['org'])[0] : null,
            'timezone'   => $info['timezone'] ?? null,
            'loc'        => $info['loc']      ?? null,
        ], fn($v) => $v !== null);
    }
}

// ─── SUBDOMAINS ───────────────────────────────────────────────────────────────
class Subdomains
{
    private const COMMON = [
        'www','mail','ftp','smtp','pop','imap','ns1','ns2','ns3','ns4',
        'api','api2','dev','staging','test','beta','cdn','static','assets',
        'blog','shop','admin','portal','vpn','remote','m','mobile','app',
        'docs','status','help','support','cloud','git','gitlab','jenkins',
        'jira','dashboard','panel','manage','mx','relay','cpanel','webmail',
    ];

    public static function run(string $input): array
    {
        $host  = HostValidator::require($input);
        $found = [];

        foreach (self::COMMON as $sub) {
            $fqdn = "$sub.$host";
            $ip   = @gethostbyname($fqdn);
            if ($ip !== $fqdn) $found[] = ['subdomain' => $fqdn, 'ip' => $ip, 'source' => 'dns_brute'];
        }

        $certSubs = [];
        try {
            $ssl = Ssl::run($host);
            foreach ($ssl['alt_names'] ?? [] as $name) {
                $name = ltrim($name, '*.');
                if ($name !== $host && str_ends_with($name, $host)) {
                    $ip = @gethostbyname($name);
                    $certSubs[] = ['subdomain' => $name, 'source' => 'ssl_cert',
                                   'ip' => $ip !== $name ? $ip : null];
                }
            }
        } catch (\Throwable) {}

        return ['host' => $host, 'found' => $found, 'cert_found' => $certSubs,
                'total' => count($found) + count($certSubs)];
    }
}

// ─── STATUS ───────────────────────────────────────────────────────────────────
class Status
{
    public static function run(string $input): array
    {
        if (!preg_match('#^https?://#i', $input)) {
            $input = 'https://' . HostValidator::sanitize($input);
        }
        $parsed  = parse_url($input);
        HostValidator::require($parsed['host'] ?? '');

        $ch = curl_init($input);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER  => true,
            CURLOPT_HEADER          => true,
            CURLOPT_NOBODY          => false,
            CURLOPT_FOLLOWLOCATION  => true,
            CURLOPT_MAXREDIRS       => CURL_MAX_REDIRECTS,
            CURLOPT_TIMEOUT         => CURL_TIMEOUT,
            CURLOPT_CONNECTTIMEOUT  => CURL_CONNECT_TIMEOUT,
            CURLOPT_SSL_VERIFYPEER  => true,
            CURLOPT_USERAGENT       => CURL_USER_AGENT,
        ]);

        $t0  = microtime(true);
        curl_exec($ch);
        $ms       = round((microtime(true) - $t0) * 1000, 2);
        $code     = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $isTLS    = curl_getinfo($ch, CURLINFO_SCHEME) === 'https';
        $finalUrl = curl_getinfo($ch, CURLINFO_EFFECTIVE_URL);
        $size     = (int)curl_getinfo($ch, CURLINFO_CONTENT_LENGTH_DOWNLOAD);
        $err      = curl_error($ch);
        curl_close($ch);

        return ['url' => $input, 'final_url' => $finalUrl, 'status_code' => $code,
                'ok' => $code >= 200 && $code < 400, 'tls' => $isTLS,
                'latency_ms' => $ms, 'content_size' => $size > 0 ? $size : null,
                'error' => $err ?: null];
    }
}

// ─── PORT SCAN ────────────────────────────────────────────────────────────────
class PortScan
{
    private const PORTS = [
        21 => 'FTP', 22 => 'SSH', 23 => 'Telnet', 25 => 'SMTP',
        53 => 'DNS', 80 => 'HTTP', 110 => 'POP3', 143 => 'IMAP',
        443 => 'HTTPS', 465 => 'SMTPS', 587 => 'SMTP/TLS',
        993 => 'IMAPS', 995 => 'POP3S', 3306 => 'MySQL',
        5432 => 'Postgres', 6379 => 'Redis', 8080 => 'HTTP-Alt',
        8443 => 'HTTPS-Alt', 27017 => 'MongoDB',
    ];

    public static function run(string $input): array
    {
        $host  = HostValidator::require($input);
        $open  = [];
        $closed = [];

        foreach (self::PORTS as $port => $service) {
            $t0   = microtime(true);
            $sock = @fsockopen($host, $port, $errno, $errstr, 1.2);
            $ms   = round((microtime(true) - $t0) * 1000, 2);
            $row  = ['port' => $port, 'service' => $service, 'ms' => $ms];
            if ($sock) { fclose($sock); $open[] = $row; } else { $closed[] = $row; }
        }

        return ['host' => $host, 'open' => $open, 'closed' => $closed,
                'open_count' => count($open), 'scanned' => count(self::PORTS)];
    }
}

// ─── REDIRECT CHAIN ───────────────────────────────────────────────────────────
class RedirectChain
{
    public static function run(string $input): array
    {
        if (!preg_match('#^https?://#i', $input)) {
            $input = 'http://' . HostValidator::sanitize($input);
        }
        $parsed = parse_url($input);
        HostValidator::require($parsed['host'] ?? '');

        $chain   = [];
        $current = $input;

        for ($i = 0; $i <= 10; $i++) {
            $ch = curl_init($current);
            curl_setopt_array($ch, [
                CURLOPT_RETURNTRANSFER  => true,
                CURLOPT_HEADER          => true,
                CURLOPT_NOBODY          => true,
                CURLOPT_FOLLOWLOCATION  => false,
                CURLOPT_TIMEOUT         => 5,
                CURLOPT_SSL_VERIFYPEER  => false,
                CURLOPT_USERAGENT       => CURL_USER_AGENT,
            ]);

            $t0       = microtime(true);
            $raw      = curl_exec($ch);
            $ms       = round((microtime(true) - $t0) * 1000, 2);
            $code     = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
            $location = '';
            if ($raw && preg_match('/^Location:\s*(.+)$/im', $raw, $lm)) {
                $location = trim($lm[1]);
            }
            curl_close($ch);

            $isTLS   = str_starts_with($current, 'https://');
            $chain[] = ['url' => $current, 'code' => $code, 'tls' => $isTLS, 'ms' => $ms];

            if ($code < 300 || $code >= 400 || !$location) break;

            if (!str_starts_with($location, 'http')) {
                $p        = parse_url($current);
                $location = ($p['scheme'] ?? 'https') . '://' . ($p['host'] ?? '') . $location;
            }
            $current = $location;
        }

        $final = end($chain);
        return [
            'start_url'   => $input,
            'final_url'   => $final['url'] ?? $input,
            'hops'        => count($chain),
            'chain'       => $chain,
            'tls_upgrade' => !str_starts_with($input, 'https://') &&
                             str_starts_with($final['url'] ?? '', 'https://'),
        ];
    }
}
