# php2shell vulnerabilities (CVE-2026-109618, CVE-2026-109619)

Operational information: 27 October 2026 15:14 CET<br>
Software list last status update: 27 October 2026 15:17 CET<br>
## TLP:CLEAR

This repository contains operational information regarding the critical PHP vulnerabilities tracked by CERT-EU as CVE-2026-109618 and CVE-2026-109619.

PHP is a widely used open-source server-side scripting language, so these vulnerabilities may affect a broad range of internet-facing web applications and products that embed or depend on PHP.

## Current status

On 21 October 2026, PHP published fixed releases for CVE-2026-109618 and CVE-2026-109619: PHP 8.5.12, 8.4.27, 8.3.36 and 8.2.35. PHP states that both vulnerabilities can allow unauthenticated remote code execution and that all PHP installations serving web requests are at risk, including PHP-FPM, Apache with mod_php, php-cgi, FrankenPHP and LiteSpeed. PHP considers the risk highest for mod_php, where an unauthenticated request can trigger exploitation before application code runs.

PHP describes CVE-2026-109618 as remote code execution via out-of-memory corruption during request cleanup, and CVE-2026-109619 as remote code execution via stale request-owned global state reused by a later request on the same worker. PHP 8.1 and older are no longer supported by the PHP project; distributions and LTS vendors may provide backported packages, and PHP has published minimal source backports for PHP 7.4, 8.0 and 8.1.

On 23 October 2026, PHP published an [informational advisory](https://www.php.net/archive/2026.php#2026-10-23-1) suggesting `session.upload_progress.enabled=0` until the next regular bugfix release to fully protect from an unlikely RCE vector (CVE-2026-115560). PHP will publish a full advisory with the next release; this repository does not track CVE-2026-115560 separately in the software list.

The impact is not limited to websites: PHP is also embedded in appliances, network devices, management interfaces and other vendor products where administrators may not be able to update PHP directly.

## Recommended actions

- Identify PHP-based applications and their runtime versions, with priority on internet-facing systems and web-serving SAPIs.
- Update to PHP 8.5.12, 8.4.27, 8.3.36 or 8.2.35, or apply vendor-provided backported packages.
- After updating, keep `session.upload_progress.enabled=0` until the next regular PHP bugfix release (PHP informational advisory of 23 October 2026, CVE-2026-115560), unless your application needs the feature and never changes `session.serialize_handler` at runtime.
- Check third-party images, appliances and embedded runtimes separately; for products that bundle PHP, apply vendor updates as soon as they become available.
- If immediate patching is not possible, follow PHP's temporary mitigations, including disabling `session.upload_progress`, restarting workers, and reviewing the official `memory_limit`, `post_max_size` and PHP 8.5 `fatal_error_backtraces` guidance. PHP states that these measures are not complete fixes.
- Monitor vendor advisories, internet-facing logs, and public exploit activity.

For additional information see:

- [CERT-EU Security Advisory 2026-018](https://cert.europa.eu/publications/security-advisories/2026-018/)
- [PHP security advisory: Critical remote code execution vulnerabilities, update now](https://www.php.net/archive/2026.php#2026-10-21-5)
- [PHP informational advisory: Session upload progress (23 October 2026)](https://www.php.net/archive/2026.php#2026-10-23-1)
- [List of advisories from other EU national CSIRT's](https://github.com/enisaeu/CNW/blob/main/advisories/2026/CNW-2026-04_php.md)

## Repository contents

| Directory | Purpose |
| --- | --- |
| [detection_mitigation](detection_mitigation) | Contains detection and mitigation material for the vulnerabilities. |
| [software](software) | Contains inventory lists of software products with a PHP dependency potentially affected by the vulnerabilities. |
| [tools](tools) | Contains tools for using/generating files within this repo |

The repository is being updated as the situation develops. Check back for updates.

## Latest software status updates

| Date and time | Supplier | Product | Version (see Status) | Status CVE-2026-109618 / CVE-2026-109619 | Links |
|:------------------------|:---------|:--------|:--------------------:|:----------------------:|------:|
|2026-10-27 15:17:18 +0100|GetPageSpeed|GetPageSpeed PHP 7.2-8.4 packages for Ubuntu 18.04/20.04 and Debian 10|Known patched builds (not necessarily first fixed revisions): bionic PHP 7.2 7.2.34-66+gps1+ubuntu1804+stable.1; buster PHP 7.3 7.3.33-35+gps1+deb10+stable.1; focal PHP 7.4 1:7.4.33-31+gps1+ubuntu2004+stable.1; PHP 8.0 1:8.0.30-25+gps1+ubuntu2004+stable.1; PHP 8.1 8.1.34-9+gps1+ubuntu2004+stable.1; PHP 8.2 8.2.35-1+gps1+ubuntu2004+stable.1; PHP 8.3 8.3.36-1+gps1+ubuntu2004+stable.1; PHP 8.4 8.4.27-1+gps1+ubuntu2004+stable.1|Fix|[source 1](<https://www.getpagespeed.com/server-setup/php/php2shell-on-ubuntu-debian>)<br>[source 2](<https://www.getpagespeed.com/php2shell>)<br>[source 3](<https://extras.getpagespeed.com/ubuntu/dists/bionic/main/binary-amd64/Packages.gz>)<br>[source 4](<https://extras.getpagespeed.com/debian/dists/buster/main/binary-amd64/Packages.gz>)<br>[source 5](<https://extras.getpagespeed.com/ubuntu/dists/focal/main/binary-amd64/Packages.gz>)|
|2026-10-27 11:55:48 +0100|Cleo|Cleo Streem (Streem Print)|Patch available by mail; fixed release not publicly stated|Fix|[source 1](<https://support.cleo.com/hc/en-us/articles/39285811298327-Cleo-Streem-Release-Notes>)<br>[source 2](<https://github.com/NCSC-NL/php2shell/pull/41>)|
|2026-10-27 11:35:19 +0100|Broadcom|CloudSOC SpanVA Appliance|Broadcom ESG advisory 39404 affected product scope|Vulnerable|[source](<https://support.broadcom.com/web/ecx/support-content-notification/-/external/content/SecurityAdvisories/Enterprise-Security-Group-Advisory-for-PHP2Shell/39404>)|
|2026-10-27 11:35:19 +0100|Broadcom|Content Analysis and Malware Analysis (CASMA)|Broadcom ESG advisory 39404 under-investigation product scope|Investigation|[source](<https://support.broadcom.com/web/ecx/support-content-notification/-/external/content/SecurityAdvisories/Enterprise-Security-Group-Advisory-for-PHP2Shell/39404>)|
|2026-10-27 11:21:24 +0100|Ubiquiti|UISP CRM (UCRM)|UISP Application 3.1.70 (CRM module)|Fix|[source 1](<https://uisp.community.ui.com/releases/UISP-Application-3-1-70/8292c6cb-4eb4-447d-9c90-455ca41b4f67>)<br>[source 2](<https://uisp.community.ui.com/questions/UCRM-4-6-15-remains-exposed-to-CVSS-9-2-RCEs-CVE-2026-109618-109619-ETA-for-PHP-8-3-36/d0fae711-2df1-4550-80e3-2b395a6a5c86>)<br>[source 3](<https://uisp.community.ui.com/releases/UISP-Application-3-1-69/d19ae117-04f7-42b3-bf53-f77d2b9e09fc>)|

See the [full software status update history](software/changelog_software_list.md).

## Contributions welcome

If you have any additional information to share relevant to these PHP vulnerabilities, feel free to open a Pull request. New to this? [Read how to contribute in GitHub's documentation](https://docs.github.com/en/repositories/working-with-files/managing-files/editing-files#editing-files-in-another-users-repository).

For updates to the software list: our strong preference is to receive edits in the SPDX source files in `software/spdx/`. The Markdown list pages are generated automatically from those files. In case this proves too difficult: don't worry. We'll attempt to backport edits in the .md files to the SPDX source files, but without any guarantees. 

