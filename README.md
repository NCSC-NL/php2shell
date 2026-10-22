# php2shell vulnerabilities (CVE-2026-109618, CVE-2026-109619)

Operational information last significant change: 21 October 2026 17:25 CEST
Software list last status update: 22 October 2026 16:13 CEST
TLP:CLEAR

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

Please note that this repository is not complete and is currently being expanded.

## Latest software status updates

| Date and time | Supplier | Product | Version (see Status) | Status CVE-2026-109618 | Status CVE-2026-109619 | Notes | Links |
|:------------------------|:---------|:--------|:--------------------:|:----------------------:|:----------------------:|:------|------:|
|2026-10-22 16:13:43 +0200|EfficientIP|EfficientIP DNS and network automation product suite||Investigation|Investigation|CVE assessment: Trusted-party reporting to NCSC-NL indicates .php URL paths in these management interfaces; exact product scope, PHP runtime details and CVE applicability are unconfirmed, and no official vendor information is available.<br>A trusted party reported to NCSC-NL that EfficientIP management interfaces for DNS and network automation products use .php URL paths; exact product scope and PHP runtime details are not publicly confirmed.|Reported to NCSC-NL by trusted party; no official vendor information available.|
|2026-10-22 16:13:43 +0200|Entelliweb|Entelliweb building management system||Investigation|Investigation|CVE assessment: Trusted-party reporting to NCSC-NL indicates .php URL paths in these management interfaces; exact product scope, PHP runtime details and CVE applicability are unconfirmed, and no official vendor information is available.<br>A trusted party reported to NCSC-NL that the Entelliweb building management system uses .php URL paths in its management interface; exact product release and PHP runtime details are not publicly confirmed.|Reported to NCSC-NL by trusted party; no official vendor information available.|
|2026-10-22 15:30:07 +0200|QNAP|QNAP Note Station 3|Note Station 3 3.9.14 and earlier|Vulnerable|Vulnerable|CVE assessment: QNAP QSA-26-18 lists these product versions as affected by both PHP2Shell CVEs; fixed versions are to be announced.<br>QNAP QSA-26-18 lists Note Station 3 3.9.14 and earlier as affected by CVE-2026-109618 and CVE-2026-109619; fixed version is to be announced.|[source](<https://www.qnap.com/en/security-advisory/qsa-26-18>)|
|2026-10-22 15:30:07 +0200|QNAP|QNAP QNE (ADRA)|QNE (ADRA) 1.0.7 and earlier|Vulnerable|Vulnerable|CVE assessment: QNAP QSA-26-18 lists these product versions as affected by both PHP2Shell CVEs; fixed versions are to be announced.<br>QNAP QSA-26-18 lists QNE (ADRA) 1.0.7 and earlier as affected by CVE-2026-109618 and CVE-2026-109619; fixed version is to be announced.|[source](<https://www.qnap.com/en/security-advisory/qsa-26-18>)|
|2026-10-22 15:30:07 +0200|QNAP|QNAP QTS built-in PHP runtime|QTS 6.1.0; QTS 5.2.11 and earlier|Vulnerable|Vulnerable|CVE assessment: QNAP QSA-26-18 lists these product versions as affected by both PHP2Shell CVEs; fixed versions are to be announced.<br>QNAP QSA-26-18 lists QTS 6.1.0 and QTS 5.2.11 and earlier as affected by CVE-2026-109618 and CVE-2026-109619; fixed versions are to be announced.|[source 1](<https://www.qnap.com/en-us/how-to/faq/article/why-i-cannot-use-php-74-after-updating-qts-quts-hero-to-520>)<br>[source 2](<https://www.qnap.com/en/how-to/faq/article/can-i-update-the-built-in-php-version-on-qts-and-quts-hero>)<br>[source 3](<https://www.qnap.com/en/security-advisory/qsa-26-18>)|

See the [full software status update history](software/changelog_software_list.md).

## Contributions welcome

If you have any additional information to share relevant to these PHP vulnerabilities, feel free to open a Pull request. New to this? [Read how to contribute in GitHub's documentation](https://docs.github.com/en/repositories/working-with-files/managing-files/editing-files#editing-files-in-another-users-repository).

For updates to the software list: our strong preference is to receive edits in the SPDX source files in `software/spdx/`. The Markdown list pages are generated automatically from those files. In case this proves too difficult: don't worry. We'll attempt to backport edits in the .md files to the SPDX source files, but without any guarantees. 

