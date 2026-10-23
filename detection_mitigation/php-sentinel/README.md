# PHP Sentinel

A reverse proxy that defends PHP applications against CVE-2026-109618 and CVE-2026-109619 (php2shell). Two layers of protection:

1. **Upload-progress filter** (primary) — blocks any multipart request containing `PHP_SESSION_UPLOAD_PROGRESS`, the shared attack surface for both CVE-2026-109618 and CVE-2026-109619. Deterministic, no latency cost.
2. **Canary array** (defense in depth) — replays every request through 11 isolated PHP-FPM instances (PHP 5.6–8.4) in parallel. If any canary worker crashes, OOMs, or hangs, the request is blocked before production sees it. Catches unknown parser bugs that the filter doesn't cover.

**Compensating control for EOL PHP versions (5.6, 7.x, 8.0, 8.1) where no vendor patch exists.**

## How it works

Sentinel sits between the internet and your PHP application. Every inbound request first passes through the upload-progress filter, which blocks the known CVE attack surface deterministically. Requests that pass the filter are then replayed in parallel through 11 isolated canary PHP-FPM instances (PHP 5.6 through 8.4). The canaries run in complete isolation: no database, no secrets, no network egress. Their only job is to parse the request. If any canary's worker segfaults, OOMs, or returns an error, the request is blocked (HTTP 403) before production ever sees it.

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

- The upload-progress filter blocks the shared attack surface for both CVE-2026-109618 and CVE-2026-109619. Both CVEs are triggered through the `session.upload_progress` handler.
- The canary array detects exploits that **crash** PHP workers. A successful RCE that runs without crashing is not caught by the canaries.
- Canaries run `memory_limit=16M`, not production's config. OOM thresholds can differ between canary and production.
- CVE-2026-109619 can corrupt worker state across multiple requests. Single-request canary replay does not reproduce multi-request heap grooming. The upload-progress filter blocks the entry point; the canaries cannot independently detect silent cross-request exploitation.
- Adds latency per request (parallel canary replay, bounded by the slowest canary). The upload-progress filter adds none.
- Requires Docker on the host system.
- Does not replace updating to fixed PHP releases where available. This is a compensating control for environments where patching is not possible.

## Links

- **Repository:** https://github.com/Taz1920/php-sentinel
- **License:** MIT
