# cPanel

This directory contains cPanel-specific mitigation material for CVE-2026-109618 and CVE-2026-109619.

| File | Purpose |
| --- | --- |
| [php2shell-mitigate.sh](php2shell-mitigate.sh) | Applies partial mitigations for cPanel EasyApache 4 PHP installations. |

See the script header and `--help` output for usage and limitations. Updating to fixed PHP packages remains the complete remediation. After updating, keep the drop-in's `session.upload_progress.enabled = 0` (do not run `--rollback`) until the next regular PHP bugfix release, per PHP's informational advisory of 23 October 2026 on CVE-2026-115560.
