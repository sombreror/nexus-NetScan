# NEXUS NetScan v2.2

Cyber network diagnostic dashboard. PHP 8.2 + MySQL. No framework.

## Project Structure

```
nexus/
├── public/                 ← Apache document root (web-accessible)
│   ├── index.html          ← UI shell (HTML only)
│   ├── style.css           ← All styles
│   ├── app.js              ← All JS (auth + tools + logs)
│   └── api.php             ← API router + auth endpoints
├── src/
│   ├── db/
│   │   ├── Database.php        ← PDO singleton
│   │   ├── Logger.php          ← Audit log writer
│   │   └── LogRepository.php   ← Logs/stats queries
│   ├── middleware/
│   │   ├── HostValidator.php   ← Input sanitizer (no whitelist)
│   │   └── RateLimiter.php     ← Per-IP rate limiting
│   └── tools/
│       ├── Ping.php            ← TCP ping (ECONNREFUSED via errno int)
│       ├── Dns.php             ← Multi-type DNS lookup
│       ├── Ssl.php             ← SSL/TLS certificate check
│       ├── Headers.php         ← HTTP headers + 8-check security score
│       └── Tools.php           ← Traceroute, Whois, Uptime, Latency,
│                                  IpInfo, Subdomains, Status, PortScan,
│                                  RedirectChain
├── config/
│   └── config.php          ← All constants (reads env vars)
├── schema.sql              ← MySQL schema (users, login_attempts, logs, rate_limits)
├── Dockerfile
├── docker-compose.yml
└── README.md
```

## Quick Start

```bash
docker-compose up -d
open http://localhost:8080
```

Register an account, then log in. All tools require authentication.

## Manual Setup

```bash
mysql -u root -p < schema.sql
```

Environment variables (or edit `config/config.php`):

```
DB_HOST=localhost
DB_NAME=nexus
DB_USER=nexus_user
DB_PASS=your_password
JWT_SECRET=long_random_string
RATE_LIMIT=60
RATE_WINDOW=60
APP_ENV=production
```

## Authentication

| Endpoint       | Method | Description                          |
|----------------|--------|--------------------------------------|
| `?action=csrf` | GET    | Get CSRF token (call before POST)    |
| `?action=register` | POST | Create account (username/email/pass) |
| `?action=login`    | POST | Login, returns session cookie + CSRF |
| `?action=logout`   | POST | Destroy session                      |
| `?action=whoami`   | GET  | Check session status                 |

- Passwords hashed with **bcrypt cost=12**
- Sessions: HttpOnly + Secure + SameSite=Strict
- Session regenerated every 5 min, destroyed on logout
- Login locked for 15 min after 5 failed attempts
- All state-changing requests require CSRF token (`X-CSRF-Token` header)

## Tools (13 total)

| Tool             | Action      | Description                                    |
|------------------|-------------|------------------------------------------------|
| Ping             | `ping`      | TCP port 80/443, DNS latency, ICMP via errno   |
| DNS Lookup       | `dns`       | A, AAAA, MX, NS, TXT, CNAME, SOA, SRV, CAA    |
| Traceroute       | `traceroute`| Hop-by-hop path analysis                       |
| WHOIS            | `whois`     | Registrar, expiry, nameservers, DNSSEC         |
| SSL Check        | `ssl`       | Cert validity, chain depth, SANs, serial       |
| HTTP Headers     | `headers`   | 8-check security score (HSTS, CSP, COEP…)     |
| Uptime           | `uptime`    | HTTP, HTTPS, DNS, SSH port probes              |
| Latency          | `latency`   | 5-sample, p95, jitter, grade                   |
| IP Info          | `ipinfo`    | Geo, ASN, org, timezone                        |
| Subdomains       | `subdomains`| DNS brute-force + SSL cert SANs                |
| Status Check     | `status`    | HTTP status, TLS, redirects, content size      |
| Port Scan        | `portscan`  | 19 common service ports                        |
| Redirect Chain   | `redirect`  | Full redirect trace, TLS upgrade detection     |

**No whitelist.** Any valid hostname or IP accepted (localhost/127.x blocked).

## Security

- No whitelist — any host/IP reachable
- Localhost and loopback (`127.x`, `::1`, `0.0.0.0`) blocked in HostValidator
- Rate limiting: 60 req/min per IP (configurable)
- CSRF token required on all POST requests
- Bcrypt password hashing (cost 12)
- Session hardening: HttpOnly, Secure, SameSite=Strict, periodic regeneration
- Lockout: 5 failed logins → 15 min block
- All errors sanitized in production (no stack traces exposed)
- Apache denies direct access to `src/` and `config/`
- Audit log: every tool call recorded with user_id, IP, duration

## Bug Fixes (from v2.1)

- `ECONNREFUSED` constant crash → fixed: use int array `[111, 10061, 61]`
- Broken config.php from partial edit → fully rewritten
- Whitelist removed → any server now scannable
- Auth added to protect all tool endpoints
