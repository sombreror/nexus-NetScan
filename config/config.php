<?php
declare(strict_types=1);

// ─── DATABASE ──────────────────────────────────────────────────────────────
define('DB_HOST', getenv('DB_HOST') ?: 'localhost');
define('DB_NAME', getenv('DB_NAME') ?: 'nexus');
define('DB_USER', getenv('DB_USER') ?: 'nexus_user');
define('DB_PASS', getenv('DB_PASS') ?: 'change_me');
define('DB_PORT', (int)(getenv('DB_PORT') ?: 3306));

// ─── RATE LIMITING ─────────────────────────────────────────────────────────
define('RATE_LIMIT',         (int)(getenv('RATE_LIMIT')  ?: 60));
define('RATE_WINDOW',        (int)(getenv('RATE_WINDOW') ?: 60));
define('LOGIN_MAX_ATTEMPTS', 5);
define('LOGIN_LOCKOUT_SEC',  900);

// ─── AUTH / SESSION ────────────────────────────────────────────────────────
define('SESSION_NAME',     'nexus_sess');
define('SESSION_LIFETIME', 3600);

// ─── CORS ──────────────────────────────────────────────────────────────────
// Empty = echo back request origin (dev-friendly). Set to specific domain in prod.
define('CORS_ORIGIN', getenv('CORS_ORIGIN') ?: '');

// ─── CURL DEFAULTS ─────────────────────────────────────────────────────────
define('CURL_TIMEOUT',         10);
define('CURL_CONNECT_TIMEOUT',  5);
define('CURL_MAX_REDIRECTS',    5);
define('CURL_USER_AGENT',       'NexusDashboard/2.3');

// ─── TOOL SETTINGS ─────────────────────────────────────────────────────────
define('LATENCY_ROUNDS',      5);
define('LATENCY_SLEEP_US',    200_000);
define('TRACEROUTE_MAX_HOPS', 15);
define('SOCKET_TIMEOUT',      3.0);

// ─── LOGS ──────────────────────────────────────────────────────────────────
define('LOG_PAGE_SIZE', 50);

// ─── ENVIRONMENT ───────────────────────────────────────────────────────────
define('APP_ENV',   getenv('APP_ENV') ?: 'production');
define('APP_DEBUG', APP_ENV === 'development');
