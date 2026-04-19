<?php
declare(strict_types=1);

// ═══════════════════════════════════════════════════════════════════════════
// NEXUS API v3 — OPEN ACCESS. No auth. No sessions. No CSRF.
// Pure JSON. All tools public.
// ═══════════════════════════════════════════════════════════════════════════

ob_start();
error_reporting(E_ALL);
ini_set('display_errors', '0');
ini_set('log_errors',     '1');
ini_set('error_log',      sys_get_temp_dir() . '/nexus_php_errors.log');

// Shutdown handler — catches any fatal PHP errors and returns JSON
register_shutdown_function(function () {
    $err = error_get_last();
    if ($err && in_array($err['type'], [E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR], true)) {
        while (ob_get_level() > 0) ob_end_clean();
        if (!headers_sent()) {
            header('Content-Type: application/json; charset=utf-8');
            http_response_code(500);
        }
        $debug = defined('APP_DEBUG') && APP_DEBUG;
        echo json_encode(['ok' => false, 'error' => $debug
            ? 'Fatal: ' . $err['message'] . ' in ' . basename($err['file']) . ':' . $err['line']
            : 'Internal server error.']);
    }
});

// Bootstrap — wrapped so any require failure returns JSON not Apache HTML
try {
    $_base = dirname(__DIR__);
    require_once $_base . '/config/config.php';
    require_once $_base . '/src/db/Database.php';
    require_once $_base . '/src/db/Logger.php';
    require_once $_base . '/src/db/LogRepository.php';
    require_once $_base . '/src/middleware/HostValidator.php';
    require_once $_base . '/src/middleware/RateLimiter.php';
    require_once $_base . '/src/tools/Ping.php';
    require_once $_base . '/src/tools/Dns.php';
    require_once $_base . '/src/tools/Ssl.php';
    require_once $_base . '/src/tools/Headers.php';
    require_once $_base . '/src/tools/Tools.php';
} catch (\Throwable $e) {
    while (ob_get_level() > 0) ob_end_clean();
    header('Content-Type: application/json; charset=utf-8');
    http_response_code(500);
    echo json_encode(['ok' => false, 'error' => 'Server configuration error: ' . $e->getMessage()]);
    exit;
}

use Nexus\Db\{Database, Logger, LogRepository};
use Nexus\Middleware\{HostValidator, RateLimiter};
use Nexus\Tools\{Ping, Dns, Ssl, Headers, Traceroute, Whois, Uptime,
                  Latency, IpInfo, Subdomains, Status, PortScan, RedirectChain};

// ─── HEADERS ─────────────────────────────────────────────────────────────────
header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Referrer-Policy: no-referrer');
header('Cache-Control: no-store, no-cache, must-revalidate');

$origin = $_SERVER['HTTP_ORIGIN'] ?? '';
if ($origin !== '') {
    $allowed = (defined('CORS_ORIGIN') && CORS_ORIGIN !== '') ? CORS_ORIGIN : $origin;
    header('Access-Control-Allow-Origin: '    . $allowed);
    header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
    header('Access-Control-Allow-Headers: Content-Type');
    header('Vary: Origin');
}

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    while (ob_get_level() > 0) ob_end_clean();
    http_response_code(204);
    exit;
}

// ─── HELPERS ─────────────────────────────────────────────────────────────────
function respond(array $payload, int $code = 200): never
{
    while (ob_get_level() > 0) ob_end_clean();
    http_response_code($code);
    $json = json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    echo ($json !== false) ? $json : '{"ok":false,"error":"JSON encoding failed"}';
    exit;
}

function fail(string $msg, int $code = 400): never
{
    respond(['ok' => false, 'error' => $msg], $code);
}

// ─── PARSE ACTION ────────────────────────────────────────────────────────────
$body   = [];
$action = trim((string)($_GET['action'] ?? ''));

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $raw = (string)file_get_contents('php://input');
    if ($raw !== '') {
        $decoded = json_decode($raw, true);
        if (json_last_error() !== JSON_ERROR_NONE || !is_array($decoded)) {
            fail('Invalid JSON body: ' . json_last_error_msg(), 400);
        }
        $body = $decoded;
    }
    if ($action === '') $action = trim((string)($body['action'] ?? ''));
}

if ($action === '') fail('Missing action parameter.', 400);

// ─── STATS ───────────────────────────────────────────────────────────────────
if ($action === 'stats') {
    try {
        respond(['ok' => true, 'data' => LogRepository::stats()]);
    } catch (\Throwable $e) {
        error_log('[NEXUS] stats: ' . $e->getMessage());
        // DB unavailable — return zeroed stats, don't crash
        respond(['ok' => true, 'data' => [
            'total' => 0, 'errors' => 0, 'success' => 0, 'today' => 0,
            'by_tool' => [], 'avg_dur' => [],
        ]]);
    }
}

// ─── LOGS ────────────────────────────────────────────────────────────────────
if ($action === 'logs') {
    try {
        $level  = (string)($_GET['level']  ?? 'ALL');
        $tool   = (string)($_GET['tool']   ?? 'ALL');
        $page   = max(1, (int)($_GET['page'] ?? 1));
        $search = trim((string)($_GET['search'] ?? ''));
        respond(['ok' => true, 'data' => LogRepository::list($level, $tool, $page, $search)]);
    } catch (\Throwable $e) {
        error_log('[NEXUS] logs: ' . $e->getMessage());
        respond(['ok' => true, 'data' => ['logs' => [], 'total' => 0, 'page' => 1, 'pages' => 1]]);
    }
}

// ─── CONNECTION SECURITY SCAN ────────────────────────────────────────────────
if ($action === 'connection_scan') {
    $host   = trim((string)($_GET['host'] ?? $body['host'] ?? ''));
    $result = [
        'server_detected_ip' => Logger::clientIP(),
        'server_https'       => (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
                             || ($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https',
    ];

    if ($host !== '') {
        try {
            $cleanHost = HostValidator::sanitize($host);
            $blocked   = ['localhost', '127.0.0.1', '::1', '0.0.0.0'];
            if ($cleanHost !== '' && !in_array($cleanHost, $blocked, true)
                && !preg_match('/^127\./', $cleanHost)) {

                // TLS cert check
                $ctx = stream_context_create(['ssl' => [
                    'capture_peer_cert' => true,
                    'verify_peer'       => true,
                    'verify_peer_name'  => true,
                    'SNI_enabled'       => true,
                    'peer_name'         => $cleanHost,
                ]]);
                $socket = @stream_socket_client(
                    "ssl://{$cleanHost}:443", $errno, $errstr, 5, STREAM_CLIENT_CONNECT, $ctx
                );
                if ($socket) {
                    $params   = stream_context_get_params($socket);
                    $certRes  = $params['options']['ssl']['peer_certificate'] ?? null;
                    fclose($socket);
                    $certInfo = $certRes ? openssl_x509_parse($certRes) : [];
                    $validTo  = isset($certInfo['validTo_time_t']) ? (int)$certInfo['validTo_time_t'] : 0;
                    $daysLeft = $validTo > 0 ? (int)(($validTo - time()) / 86400) : -1;
                    $result['tls'] = [
                        'supported' => true,
                        'host'      => $cleanHost,
                        'valid'     => $daysLeft > 0,
                        'days_left' => $daysLeft,
                        'issuer'    => $certInfo['issuer']['O']   ?? 'Unknown',
                        'subject'   => $certInfo['subject']['CN'] ?? $cleanHost,
                    ];
                } else {
                    $result['tls'] = ['supported' => false, 'host' => $cleanHost,
                                      'error' => $errstr ?: 'TLS connect failed'];
                }

                // HTTP security headers grade
                $ch = curl_init("https://{$cleanHost}");
                if ($ch !== false) {
                    curl_setopt_array($ch, [
                        CURLOPT_RETURNTRANSFER => true,
                        CURLOPT_HEADER         => true,
                        CURLOPT_NOBODY         => true,
                        CURLOPT_TIMEOUT        => 8,
                        CURLOPT_CONNECTTIMEOUT => 4,
                        CURLOPT_FOLLOWLOCATION => true,
                        CURLOPT_MAXREDIRS      => 3,
                        CURLOPT_USERAGENT      => CURL_USER_AGENT,
                        CURLOPT_SSL_VERIFYPEER => false,
                    ]);
                    $resp     = curl_exec($ch);
                    $httpCode = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
                    curl_close($ch);
                    $hdrs = [];
                    if ($resp) {
                        foreach (explode("\r\n", (string)$resp) as $line) {
                            if (str_contains($line, ':')) {
                                [$k, $v] = explode(':', $line, 2);
                                $hdrs[strtolower(trim($k))] = trim($v);
                            }
                        }
                    }
                    $checks = [
                        'HSTS'               => isset($hdrs['strict-transport-security']),
                        'CSP'                => isset($hdrs['content-security-policy']),
                        'X-Frame-Options'    => isset($hdrs['x-frame-options']),
                        'X-Content-Type'     => isset($hdrs['x-content-type-options']),
                        'Referrer-Policy'    => isset($hdrs['referrer-policy']),
                        'Permissions-Policy' => isset($hdrs['permissions-policy']),
                    ];
                    $score = count(array_filter($checks));
                    $max   = count($checks);
                    $grade = $score >= 6 ? 'A' : ($score >= 4 ? 'B' : ($score >= 2 ? 'C' : 'D'));
                    $result['headers'] = compact('httpCode', 'checks', 'score', 'max', 'grade');
                    $result['headers']['http_code'] = $httpCode;
                }
            }
        } catch (\Throwable $e) {
            error_log('[NEXUS] connection_scan: ' . $e->getMessage());
            $result['scan_error'] = 'Scan failed.';
        }
    }

    respond(['ok' => true, 'data' => $result]);
}

// ─── TOOL ACTIONS — open access, rate limited ─────────────────────────────────
RateLimiter::check();

$target = trim((string)($body['target'] ?? $_GET['target'] ?? ''));
if ($target === '')         fail('Missing target parameter.');
if (strlen($target) > 253)  fail('Target too long.');

$ip = Logger::clientIP();
$t0 = microtime(true);
$res   = [];
$level = 'INFO';

try {
    switch ($action) {
        case 'ping':       $res = Ping::run($target);          $level = $res['reachable']        ? 'SUCCESS' : 'WARN';  break;
        case 'dns':        $res = Dns::run($target);           $level = $res['count'] > 0        ? 'SUCCESS' : 'WARN';  break;
        case 'traceroute': $res = Traceroute::run($target);    $level = 'INFO';                                         break;
        case 'whois':      $res = Whois::run($target);         $level = $res['found']            ? 'SUCCESS' : 'WARN';  break;
        case 'ssl':        $res = Ssl::run($target);           $level = ($res['valid'] ?? false) ? 'SUCCESS' : 'ERROR'; break;
        case 'headers':    $res = Headers::run($target);       $level = (($res['status_code'] ?? 0) >= 200 && ($res['status_code'] ?? 0) < 400) ? 'SUCCESS' : 'WARN'; break;
        case 'uptime':     $res = Uptime::run($target);        $level = $res['up']               ? 'SUCCESS' : 'ERROR'; break;
        case 'latency':    $res = Latency::run($target);       $level = 'INFO';                                         break;
        case 'ipinfo':     $res = IpInfo::run($target);        $level = isset($res['error'])     ? 'ERROR'   : 'SUCCESS'; break;
        case 'subdomains': $res = Subdomains::run($target);    $level = 'INFO';                                         break;
        case 'status':     $res = Status::run($target);        $level = ($res['ok'] ?? false)    ? 'SUCCESS' : 'ERROR'; break;
        case 'portscan':   $res = PortScan::run($target);      $level = 'INFO';                                         break;
        case 'redirect':   $res = RedirectChain::run($target); $level = 'INFO';                                         break;
        default:           fail('Unknown action: ' . substr(htmlspecialchars($action, ENT_QUOTES), 0, 32));
    }
} catch (\InvalidArgumentException $e) {
    fail($e->getMessage(), 400);
} catch (\Throwable $e) {
    $ms = (int)round((microtime(true) - $t0) * 1000);
    error_log('[NEXUS] tool [' . $action . ']: ' . $e->getMessage());
    Logger::write($action, $target, 'ERROR', 'Tool failed.', $ms, null);
    fail(APP_DEBUG ? $e->getMessage() : 'Tool execution failed.', 500);
}

$ms = (int)round((microtime(true) - $t0) * 1000);
Logger::write($action, $target, $level, $res, $ms, null);
respond(['ok' => true, 'action' => $action, 'duration_ms' => $ms, 'data' => $res]);
