# php2shell vulnerabilities (CVE-2026-109618, CVE-2026-109619)

Operational information: 21 October 2026 17:25 CEST<br>
Software list last status update: 23 October 2026 14:46 CEST<br>
## TLP:CLEAR

This repository contains operational information regarding the critical PHP vulnerabilities tracked by CERT-EU as CVE-2026-109618 and CVE-2026-109619.

PHP is a widely used open-source server-side scripting language, so these vulnerabilities may affect a broad range of internet-facing web applications and products that embed or depend on PHP.

## Current status

On 21 October 2026, PHP published fixed releases for CVE-2026-109618 and CVE-2026-109619: PHP 8.5.12, 8.4.27, 8.3.36 and 8.2.35. PHP states that both vulnerabilities can allow unauthenticated remote code execution and that all PHP installations serving web requests are at risk, including PHP-FPM, Apache with mod_php, php-cgi, FrankenPHP and LiteSpeed. PHP considers the risk highest for mod_php, where an unauthenticated request can trigger exploitation before application code runs.

PHP describes CVE-2026-109618 as remote code execution via out-of-memory corruption during request cleanup, and CVE-2026-109619 as remote code execution via stale request-owned global state reused by a later request on the same worker. PHP 8.1 and older are no longer supported by the PHP project; distributions and LTS vendors may provide backported packages, and PHP has published minimal source backports for PHP 7.4, 8.0 and 8.1.

The impact is not limited to websites: PHP is also embedded in appliances, network devices, management interfaces and other vendor products where administrators may not be able to update PHP directly.

## Recommended actions

- Identify PHP-based applications and their runtime versions, with priority on internet-facing systems and web-serving SAPIs.
- Update to PHP 8.5.12, 8.4.27, 8.3.36 or 8.2.35, or apply vendor-provided backported packages.
- Check third-party images, appliances and embedded runtimes separately; for products that bundle PHP, apply vendor updates as soon as they become available.
- If immediate patching is not possible, follow PHP's temporary mitigations, including disabling `session.upload_progress`, restarting workers, and reviewing the official `memory_limit`, `post_max_size` and PHP 8.5 `fatal_error_backtraces` guidance. PHP states that these measures are not complete fixes.
- Monitor vendor advisories, internet-facing logs, and public exploit activity.

For additional information see:

- [CERT-EU Security Advisory 2026-018](https://cert.europa.eu/publications/security-advisories/2026-018/)
- [PHP security advisory: Critical remote code execution vulnerabilities, update now](https://www.php.net/archive/2026.php#2026-10-21-5)
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
|2026-10-23 14:46:29 +0200|Broadcom|Symantec Endpoint Protection Manager (SEPM)|14.3.27716.10000 / 14.4.494.0000|Fix|[source 1](<https://support.broadcom.com/web/ecx/support-content-notification/-/external/content/SecurityAdvisories/Enterprise-Security-Group-Advisory-for-PHP2Shell/39404>)<br>[source 2](<https://support.broadcom.com/web/ecx/support-content-notification/-/external/content/SecurityAdvisories/Symantec-Endpoint-Protection-Security-Update-for-PHP2Shell/39421>)<br>[source 3](<https://github.com/NCSC-NL/php2shell/issues/30>)|
|2026-10-23 14:46:29 +0200|Hewlett Packard Enterprise|HPE Networking ClearPass Policy Manager|6.14.0 and below / 6.11.15 and below; 6.14.1 / 6.11.16 partially mitigated, still affected|Vulnerable|[source](<https://support.hpe.com/hpesc/public/docDisplay?docId=hpesbnw05171en_us&docLocale=en_US>)|
|2026-10-23 14:46:29 +0200|NetApp|ONTAP 9|ONTAP 9; affected maintenance releases and fixed releases not specified|Vulnerable/Not vuln|[source](<https://security.netapp.com/advisory/NTAP-20261021-0021>)|
|2026-10-23 13:48:52 +0200|Cisco|Cisco Expressway Select Series|Expressway Select Series; affected release range not specified|Vulnerable|[source](<https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-php-october26-Jj384Daq>)|
|2026-10-23 13:48:52 +0200|Cisco|Cisco Identity Services Engine (ISE) Portal Builder||Investigation|[source](<https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-php-october26-Jj384Daq>)|

See the [full software status update history](software/changelog_software_list.md).

## Contributions welcome

If you have any additional information to share relevant to these PHP vulnerabilities, feel free to open a Pull request. New to this? [Read how to contribute in GitHub's documentation](https://docs.github.com/en/repositories/working-with-files/managing-files/editing-files#editing-files-in-another-users-repository).

For updates to the software list: our strong preference is to receive edits in the SPDX source files in `software/spdx/`. The Markdown list pages are generated automatically from those files. In case this proves too difficult: don't worry. We'll attempt to backport edits in the .md files to the SPDX source files, but without any guarantees. 

