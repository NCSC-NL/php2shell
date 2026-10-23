# Scanning and verification

This page covers how to determine whether a PHP installation is exposed to
CVE-2026-109618 and CVE-2026-109619, and the pitfalls that cause both false
negatives and false positives.

Temporary mitigations do not replace updating to fixed PHP releases or
vendor-provided backports.

## Fixed versions

| Branch | Fixed in |
| --- | --- |
| 8.5 | 8.5.12 |
| 8.4 | 8.4.27 |
| 8.3 | 8.3.36 |
| 8.2 | 8.2.35 |
| 8.1 and older | No upstream release. Source backports and vendor packages only. |

## Pitfalls when determining exposure

- **Distribution packages backport fixes without changing the upstream version
  number.** A host reporting an older version may already carry the fix. Confirm
  against the vendor advisory rather than the version string alone.
- **The version reported by the `php` CLI is not necessarily the version serving
  requests.** `php`, `php-fpm` and `mod_php` can be separate builds reading
  separate ini files. Verify the SAPI that actually handles web traffic.
- **`X-Powered-By` is unreliable.** It is frequently disabled, and can be stale
  or deliberately misleading. Treat a header-based verdict as a hint only.
- **Container images and running containers drift apart.** Patching a running
  container leaves the image exposed, and the next deployment reintroduces it.
- **Restart all PHP workers after patching.** Long-lived FPM workers continue
  executing pre-patch code.

## Tooling

Community scanners are listed under
[Community tools](../README.md#community-tools). They are not reviewed or
endorsed by NCSC-NL. Before running one, check whether it inspects passively or
sends crafted probe traffic: the latter requires authorization when aimed at
systems you do not own.

## Verifying mitigations

Where patching cannot be completed immediately, the interim settings are
`memory_limit=-1` (set so applications cannot override it),
`session.upload_progress.enabled=0`, and on 8.5 additionally
`fatal_error_backtraces=0`.

Confirm the setting is actually in effect for the SAPI serving requests, not
only for the CLI. All PHP workers must be restarted afterwards. Container
memory limits and WAF rules reduce opportunity but are not mitigations.

On 23 October 2026 PHP published an
[informational advisory](https://www.php.net/archive/2026.php#2026-10-23-1)
recommending that `session.upload_progress.enabled=0` be kept in place also on
fixed releases, until the next regular bugfix release, because of an
additional vector, CVE-2026-115560. A host on a fixed version with session
upload progress still enabled should therefore not be reported as fully
remediated unless the application never changes `session.serialize_handler`
at runtime. The other temporary settings are no longer needed once a fixed
release is installed.
