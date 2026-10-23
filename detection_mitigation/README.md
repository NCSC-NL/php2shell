# Detection and mitigation

This directory contains detection and mitigation material related to CVE-2026-109618 and CVE-2026-109619.

The material here is intended as operational guidance and should be tested before use in production environments. Temporary mitigations do not replace updating to fixed PHP releases or vendor-provided backports.

## Available material

| Directory | Purpose |
| --- | --- |
| [cpanel](cpanel) | cPanel EasyApache 4 mitigation material. |
| [version_check](version_check) | Self-deleting file that reports the exact PHP runtime version a site is served with. |

## Community tools

Tools in this section are contributed by the community and are not reviewed or endorsed by NCSC-NL; evaluate them before use in your environment.

| Tool | Purpose |
| --- | --- |
| [php2shell-guard](https://github.com/hezhidong/php2shell-guard) | Cross-platform (Windows, Linux, macOS) zero-dependency Python CLI. Detects all local PHP installations (PATH, registry, common directories, Homebrew, scoop) and classifies exposure to CVE-2026-109618 / CVE-2026-109619 by version, can apply the temporary ini mitigations or upgrade via the system package manager, and re-verifies afterwards. Also reports running PHP processes and PHP containers in Docker. |
