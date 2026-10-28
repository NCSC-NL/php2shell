# php2shell vulnerabilities (CVE-2026-109618, CVE-2026-109619)

Operational information: 27 October 2026 15:14 CET<br>
Software list last status update: 28 October 2026 11:14 CET<br>
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
|2026-10-28 11:14:56 +0100|Palo Alto Networks|PAN-OS|Fixed thresholds in PAN-OS 12.2.4-h1; 12.1.4-h13 (ETA 2026-10-29), 12.1.7-h11, 12.1.10-h3 (ETA 2026-10-30); 11.2.4-h23 (ETA 2026-10-30), 11.2.7-h23, 11.2.10-h16, 11.2.13-h4, 11.2.16-h1; 11.1.4-h38, 11.1.6-h40, 11.1.7-h12 (ETA 2026-10-30), 11.1.10-h36, 11.1.13-h16, 11.1.16-h4; 10.2.7-h39 (ETA 2026-10-30), 10.2.10-h42 (ETA 2026-10-29), 10.2.13-h27, 10.2.16-h12, 10.2.18-h13; earlier builds affected|Fix|[source 1](<https://docs.paloaltonetworks.com/oss-listings/pan-os-oss-listings/pan-os-12-2-open-source-software-oss-listing>)<br>[source 2](<https://security.paloaltonetworks.com/CVE-2025-0108>)<br>[source 3](<https://security.paloaltonetworks.com/CVE-2026-109618>)|
|2026-10-28 11:14:56 +0100|Palo Alto Networks|Panorama|Fixed thresholds in Panorama 12.2.4-h1; 12.1.4-h13 (ETA 2026-10-29), 12.1.7-h11, 12.1.10-h3 (ETA 2026-10-30); 11.2.4-h23 (ETA 2026-10-30), 11.2.7-h23, 11.2.10-h16, 11.2.13-h4, 11.2.16-h1; 11.1.4-h38, 11.1.6-h40, 11.1.7-h12 (ETA 2026-10-30), 11.1.10-h36, 11.1.13-h16, 11.1.16-h4; 10.2.7-h39 (ETA 2026-10-30), 10.2.10-h42 (ETA 2026-10-29), 10.2.13-h27, 10.2.16-h12, 10.2.18-h13; earlier builds affected|Fix|[source 1](<https://docs.paloaltonetworks.com/oss-listings/panorama-oss-listings/panorama-12-2-open-source-software-oss-listing>)<br>[source 2](<https://docs.paloaltonetworks.com/panorama/getting-started/panorama-overview/about-panorama>)<br>[source 3](<https://security.paloaltonetworks.com/CVE-2026-109618>)|
|2026-10-28 10:58:25 +0100|Citrix / NetScaler|Citrix NetScaler ADC and Citrix NetScaler Gateway|Fixed in NetScaler ADC and Gateway 14.1-73.49 and later; 13.1-64.32 and later releases of 13.1; ADC 14.1-FIPS 14.1-73.49 FIPS and later; ADC 13.1-FIPS and 13.1-NDcPP 13.1.37.286 and later; earlier builds impacted|Fix|[source 1](<https://www.citrix.com/content/dam/citrix/en_us/documents/downloads/netscaler-adc/NetScaler_ADC_ADM_FreeBSD_14.1_Third_Party_Notices.pdf>)<br>[source 2](<https://prod-docs.netscaler.com/en-us/citrix-adc/current-release/application-firewall/signatures/signature-auto-update>)<br>[source 3](<https://support.citrix.com/external/article/CTX697263/citrix-security-advisory-for-cve20261096.html>)<br>[source 4](<https://community.citrix.com/techzone-blogs/110_security-updates/protecting-netscaler-management-access-from-php-cve-2026-109618-cve-2026-109619-r1640/>)|
|2026-10-28 10:44:24 +0100|Securepoint GmbH|Securepoint Resellerportal|Patched before 2026-10-22 inventory entry; fixed release not publicly stated|Fix|[source 1](<https://my.securepoint.de/>)<br>[source 2](<https://laravel.com/framework/docs/deployment>)<br>[source 3](<https://github.com/NCSC-NL/php2shell/issues/58>)<br>[source 4](<https://github.com/NCSC-NL/php2shell/pull/10>)|
|2026-10-27 15:17:18 +0100|GetPageSpeed|GetPageSpeed PHP 7.2-8.4 packages for Ubuntu 18.04/20.04 and Debian 10|Known patched builds (not necessarily first fixed revisions): bionic PHP 7.2 7.2.34-66+gps1+ubuntu1804+stable.1; buster PHP 7.3 7.3.33-35+gps1+deb10+stable.1; focal PHP 7.4 1:7.4.33-31+gps1+ubuntu2004+stable.1; PHP 8.0 1:8.0.30-25+gps1+ubuntu2004+stable.1; PHP 8.1 8.1.34-9+gps1+ubuntu2004+stable.1; PHP 8.2 8.2.35-1+gps1+ubuntu2004+stable.1; PHP 8.3 8.3.36-1+gps1+ubuntu2004+stable.1; PHP 8.4 8.4.27-1+gps1+ubuntu2004+stable.1|Fix|[source 1](<https://www.getpagespeed.com/server-setup/php/php2shell-on-ubuntu-debian>)<br>[source 2](<https://www.getpagespeed.com/php2shell>)<br>[source 3](<https://extras.getpagespeed.com/ubuntu/dists/bionic/main/binary-amd64/Packages.gz>)<br>[source 4](<https://extras.getpagespeed.com/debian/dists/buster/main/binary-amd64/Packages.gz>)<br>[source 5](<https://extras.getpagespeed.com/ubuntu/dists/focal/main/binary-amd64/Packages.gz>)|

See the [full software status update history](software/changelog_software_list.md).

## Contributions welcome

If you have any additional information to share relevant to these PHP vulnerabilities, feel free to open a Pull request. New to this? [Read how to contribute in GitHub's documentation](https://docs.github.com/en/repositories/working-with-files/managing-files/editing-files#editing-files-in-another-users-repository).

For updates to the software list: our strong preference is to receive edits in the SPDX source files in `software/spdx/`. The Markdown list pages are generated automatically from those files. In case this proves too difficult: don't worry. We'll attempt to backport edits in the .md files to the SPDX source files, but without any guarantees. 

