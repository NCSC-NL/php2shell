# Detection and mitigation

This directory contains detection and mitigation material related to CVE-2026-109618 and CVE-2026-109619.

The material here is intended as operational guidance and should be tested before use in production environments. Temporary mitigations do not replace updating to fixed PHP releases or vendor-provided backports.

## Available material

| Directory | Purpose |
| --- | --- |
| [cpanel](cpanel) | cPanel EasyApache 4 mitigation material. |
| [scanning](scanning) | Determining exposure, common verification pitfalls, and confirming mitigations are in effect. |


## Community tools

Tools in this section are contributed by the community and are not reviewed or endorsed by NCSC-NL; evaluate them before use in your environment.

| Tool | Purpose |
| --- | --- |
| [php2shell-guard](https://github.com/hezhidong/php2shell-guard) | Cross-platform (Windows, Linux, macOS) zero-dependency Python CLI. Detects all local PHP installations (PATH, registry, common directories, Homebrew, scoop) and classifies exposure to CVE-2026-109618 / CVE-2026-109619 by version, can apply the temporary ini mitigations or upgrade via the system package manager, and re-verifies afterwards. Also reports running PHP processes and PHP containers in Docker. |
| [php2shell-check](https://github.com/adityaaravind/php2shell-check) | Read-only, zero-dependency Node.js CLI. Classifies exposure to CVE-2026-109618 / CVE-2026-109619 by version and ini settings across local PHP binaries, Docker images, running containers (CLI and PHP-FPM probed separately, as their ini can differ), inventory files and URLs (passive `X-Powered-By` only). Can preview the effect of the temporary ini mitigations before rollout. Outputs terminal, JSON, Markdown or HTML, and ships a GitHub Action that fails a build on an exposed image. Sends no probe traffic. |
