# PHP Sentinel

A reverse proxy that protects PHP applications from parser-level exploits by replaying every HTTP request through an array of isolated canary PHP-FPM instances. If any canary worker crashes, OOMs, or hangs, the request is blocked before production ever sees it.

**Specifically designed to protect EOL PHP versions (5.6, 7.x, 8.0, 8.1) where no vendor patch exists for CVE-2026-109618 and CVE-2026-109619.**

## How it works

Sentinel sits between the internet and your PHP application. Every inbound request is replayed in parallel through 11 isolated canary PHP-FPM instances (PHP 5.6 through 8.4). The canaries run in complete isolation: no database, no secrets, no network egress. Their only job is to parse the request. If any canary's worker segfaults, OOMs, or returns an error, the request is blocked (HTTP 403) before production ever sees it.

Additionally, Sentinel blocks any multipart request containing `PHP_SESSION_UPLOAD_PROGRESS` by default, which is the root attack surface for both CVEs.

## Deployment

Requires Docker. Three commands:

```bash
git clone https://github.com/Taz1920/php-sentinel.git
cd php-sentinel
docker compose build && docker compose up -d
```

Set `SENTINEL_BACKEND_URL` in `docker-compose.yml` to your PHP application's address. Dashboard available at `/__sentinel/dashboard`.

## Test results

Tested against four independent public PoC exploit tools targeting CVE-2026-109618 and CVE-2026-109619:

| PoC | Attack type | Result |
| --- | --- | --- |
| eness/php2shell-PoC | Full 3-stage heap exploit chain | Blocked (HEAP_LEAK_FAILED) |
| murrez/php2shell | CVE-2026-109618 UAF trigger | Neutered (could not arm) |
| ikow/php2shell-poc | 4-tier scanner + active OOM probe | Blocked |
| ikow/php2shell-poc | OOM header bomb (5000 headers) | Blocked (403) |
| ikow/php2shell-poc | Session filename injection | Blocked (upload_progress filter) |

## Limitations

- Adds approximately 50ms of latency per request (parallel canary replay).
- Requires Docker on the host system.
- Does not replace updating to fixed PHP releases where available. This is a compensating control for environments where patching is not possible.

## Links

- **Repository:** https://github.com/Taz1920/php-sentinel
- **License:** MIT
