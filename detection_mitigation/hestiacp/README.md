# HestiaCP

This directory contains HestiaCP-specific mitigation material for CVE-2026-109618 and CVE-2026-109619 ("PHP2Shell").

| File | Purpose |
| --- | --- |
| [hestiacp-mitigate.sh](hestiacp-mitigate.sh) | Applies partial mitigations for HestiaCP internal PHP (`hestia-php`) and multi-PHP FPM pools. |

## Overview

HestiaCP environments use two separate PHP layers:
1. **Internal backend PHP (`hestia-php`):** Runs the control panel web interface on port 8083 (`/usr/local/hestia/php/lib/php.ini` or `/usr/local/hestia/php/etc/php.ini`).
2. **Hosted multi-PHP pools:** Independent PHP-FPM pools for hosted websites (`/etc/php/*/fpm/pool.d/*.conf`).

The script applies the recommended temporary mitigations:
- `session.upload_progress.enabled = 0` (neutralizes the UAF consumer path for CVE-2026-109619)
- `memory_limit = -1` (prevents premature out-of-memory bailout during multipart header parsing for CVE-2026-109618)
- Sets conservative `post_max_size` (default 32M)

For older EOL PHP versions (5.6, 7.4, 8.0, 8.1) hosted via multi-PHP that do not receive official upstream distribution updates, source backports are also available in community repositories (such as [Anton-Barinov/php2shell-patches](https://github.com/Anton-Barinov/php2shell-patches)).

> **Note:** As emphasized in the official PHP advisory, only updating to patched releases is a complete remediation. Mitigations buy time and reduce exposure.
