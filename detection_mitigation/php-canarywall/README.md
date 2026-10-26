# PHP CanaryWall

> Formerly known as PHP Sentinel. If you followed an old link or reference, you're in the right place — GitHub redirects the old URL automatically.

A reverse proxy that defends PHP applications against CVE-2026-109618 and the known public exploits for CVE-2026-109619 (php2shell). Two layers of protection:

1. **Upload-progress filter** (primary) — blocks any multipart request containing `PHP_SESSION_UPLOAD_PROGRESS`, the attack surface used by CVE-2026-109618 and all known public CVE-2026-109619 exploits. Deterministic, no latency cost. Note: CVE-2026-109619 has other confirmed trigger paths (e.g. `fatal_error_backtraces` on PHP 8.5 mod_php) that do not go through upload progress — the filter does not cover those.
2. **Canary array** (defense in depth) — replays every request through 11 isolated PHP-FPM instances (PHP 5.6–8.4) in parallel. If any canary worker crashes, OOMs, or hangs, the request is blocked before production sees it. Catches unknown parser bugs that the filter doesn't cover.

**Designed as a compensating control for EOL PHP versions (5.6, 7.x, 8.0, 8.1) where no vendor patch exists.**

## How it works

CanaryWall sits between the internet and your PHP application. Every inbound request first passes through the upload-progress filter, which blocks the known CVE attack surface deterministically. Requests that pass the filter are then replayed in parallel through 11 isolated canary PHP-FPM instances (PHP 5.6 through 8.4). The canaries run in complete isolation: no database, no secrets, no network egress. Their only job is to parse the request. If any canary's worker segfaults, OOMs, or returns an error, the request is blocked (HTTP 403) before production ever sees it.

## Deployment

Requires Docker. Three commands:

```bash
git clone https://github.com/Taz1920/PHP-Canarywall.git
cd PHP-Canarywall
docker compose build && docker compose up -d
```

Set `SENTINEL_BACKEND_URL` in `docker-compose.yml` to your PHP application's address. Dashboard available at `/__sentinel/dashboard`.

Also supports standalone Docker (single canary), bare metal (no Docker), and Kubernetes deployment. See the [full README](https://github.com/Taz1920/PHP-Canarywall#readme) for details.

## Features

- **Multi-version canary array** — 11 PHP versions (5.6–8.4) running in parallel
- **Upload-progress filter** — deterministic blocking of the known CVE attack surface
- **Admin API + dashboard** — enable/disable canaries at runtime, view health and attack metrics
- **Webhook / SIEM integration** — send block alerts to CrowdStrike, Splunk, Elastic, Datadog, Slack, etc.
- **Shadow mode** — log-only mode for piloting before enforcing
- **Request size controls** — configurable body size limits with canary bypass for large uploads
- **Block logging** — every blocked request logged with sanitized headers (JSONL), auto-rotated
- **Admin authentication** — API key protection for admin endpoints, with optional separate admin port

## Test results

Tested against four independent public PoC exploit tools targeting CVE-2026-109618 and CVE-2026-109619:

| PoC | Attack type | Result |
| --- | --- | --- |
| eness/php2shell-PoC | Full 3-stage heap exploit chain | Blocked (HEAP_LEAK_FAILED) |
| murrez/php2shell | CVE-2026-109618 UAF trigger | Neutered (could not arm) |
| ikow/php2shell-poc | 4-tier scanner + active OOM probe | Blocked |
| ikow/php2shell-poc | OOM header bomb (5000 headers) | Blocked (403) |
| ikow/php2shell-poc | Session filename injection | Blocked (upload_progress filter) |
| [Taz1920/cve-2026-109619](https://github.com/Taz1920/cve-2026-109619) | CVE-2026-109619 stale session state → RCE | **Blocked (confirmed RCE prevented).** Positive control: exploit achieves full RCE on PHP 8.4.26 without CanaryWall. With CanaryWall: filter ON blocks all requests at proxy; filter OFF crashes all 11 canaries (403). |

WordPress false-positive pilot: 57 legitimate requests (pages, admin, login, uploads, REST API, XML-RPC, AJAX, static assets), 0 false positives.

## Limitations

- The upload-progress filter blocks the attack surface used by CVE-2026-109618 and all known public CVE-2026-109619 exploits. However, CVE-2026-109619 is a stale-state bug with multiple confirmed trigger paths — `session.upload_progress` is one, but `fatal_error_backtraces` on PHP 8.5 mod_php is another that does not involve upload progress. The filter does not cover trigger paths that bypass upload progress.
- The canary array detects exploits that **crash** PHP workers. A successful RCE that runs without crashing is not caught by the canaries.
- Canaries run `memory_limit=16M`. Keep this at or below production's `memory_limit` — CVE-2026-109618 is triggered by hitting the OOM handler, so the canary must reach that limit before production does.
- CVE-2026-109619 can corrupt worker state across multiple requests. Single-request canary replay does not reproduce multi-request heap grooming.
- Adds latency per request (parallel canary replay, bounded by the slowest canary). The upload-progress filter adds none.
- **PHP 8.5 mod_php users:** Set `fatal_error_backtraces=0` in php.ini alongside deploying CanaryWall. PHP 8.5 introduced a backtrace feature that creates a separate CVE-2026-109619 trigger path not involving upload progress. This is irrelevant for PHP 8.4 and earlier and for PHP-FPM. PHP 8.5 users should update to 8.5.12.
- Requires Docker on the host system (for the default deployment; bare metal is also supported).
- Does not replace updating to fixed PHP releases where available. This is a compensating control for environments where patching is not possible.

## Links

- **Repository:** https://github.com/Taz1920/PHP-Canarywall
- **License:** MIT
