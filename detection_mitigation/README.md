# Detection and mitigation

This directory contains detection and mitigation material related to CVE-2026-109618 and CVE-2026-109619.

The material here is intended as operational guidance and should be tested before use in production environments. Temporary mitigations do not replace updating to fixed PHP releases or vendor-provided backports.

## Available material

| Directory | Purpose |
| --- | --- |
| [cpanel](cpanel) | cPanel EasyApache 4 mitigation material. |


## Community tools

Tools in this section are contributed by the community and are not reviewed or endorsed by NCSC-NL; evaluate them before use in your environment.

| Tool | Purpose |
| --- | --- |
| [php2shell-guard](https://github.com/hezhidong/php2shell-guard) | Cross-platform (Windows, Linux, macOS) zero-dependency Python CLI. Detects all local PHP installations (PATH, registry, common directories, Homebrew, scoop) and classifies exposure to CVE-2026-109618 / CVE-2026-109619 by version, can apply the temporary ini mitigations or upgrade via the system package manager, and re-verifies afterwards. Also reports running PHP processes and PHP containers in Docker. |
| [php2shell-doctor](https://github.com/andreysheva/php2shell-doctor) | Cross-platform (Windows, Linux, macOS) single static Go binary, stdlib-only, offline. Classifies every local PHP runtime — distro packages against a versioned vendor-fix database (Ubuntu/Debian revisions, RHEL errata policy, Alpine, remi, sury, cPanel, Plesk, official images), panels, source builds, Docker images and containers — detects workers still running pre-upgrade code, audits the config surface (session.upload_progress incl. CVE-2026-115560, memory_limit, per-directory overrides), hunts logs for exploitation signatures, and looks up appliances in the NCSC-NL SPDX inventory. Read-only by default; exit codes plus JSON/CSV/SARIF/CycloneDX output for CI and fleet use. |
