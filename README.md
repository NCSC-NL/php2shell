# php2shell vulnerabilities (CVE-2026-109618, CVE-2026-109619)

Operational information: 28 October 2026 16:46 CET<br>
Software list last status update: 29 October 2026 09:57 CET<br>
## TLP:CLEAR

This repository contains operational information regarding the critical PHP vulnerabilities tracked by CERT-EU as CVE-2026-109618 and CVE-2026-109619.

PHP is a widely used open-source server-side scripting language, so these vulnerabilities may affect a broad range of internet-facing web applications and products that embed or depend on PHP.

## Current status

<!-- inventory-statistics:summary:start -->
This repository tracks **757 products**, including **218 vulnerable** and **152 fixed**.
<!-- inventory-statistics:summary:end -->

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
- [PHP2shell observations in the wild (TU Delft)](https://php2shell.delftintellab.com/)

## Repository contents

| Directory | Purpose |
| --- | --- |
| [detection_mitigation](detection_mitigation) | Contains detection and mitigation material for the vulnerabilities. |
| [software](software) | Contains inventory lists of software products with a PHP dependency potentially affected by the vulnerabilities. |
| [tools](tools) | Contains tools for using/generating files within this repo |
| [Community contributions](COMMUNITY_CONTRIBUTIONS.MD) | Community tools, tips, guides, and reference resources. |

The repository is being updated as the situation develops. Check back for updates.

## Software inventory statistics

<!-- inventory-statistics:start -->

Statistics as of **2026-10-29 (UTC)**, from the current SPDX inventory.

| Products tracked | Fixed | Vulnerable | Under investigation | Not affected | Unassessed / unknown |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 757 | 152 | 218 | 346 | 40 | 1 |

![Product status on the last 3 inventory update days](software/statistics/inventory-statistics.png)

[Counts by update day and per-CVE statistics (JSON)](software/statistics/inventory-statistics.json) | [Software list](software/software_list.md)

<!-- inventory-statistics:end -->

## Latest software status updates

| Date and time | Supplier | Product | Version (see Status) | Status CVE-2026-109618 / CVE-2026-109619 | Links |
|:------------------------|:---------|:--------|:--------------------:|:----------------------:|------:|
|2026-10-29 09:57:47 +0100|Acquia|Acquia Cloud Platform PHP hosting|Cloud Platform 2026-10-22: PHP 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12|Fix|[source 1](<https://docs.acquia.com/acquia-cloud-platform/configuring-php-settings>)<br>[source 2](<https://docs.acquia.com/acquia-cloud-platform/release/2026-10-22/100321-cloud-platform-october-22-2026>)<br>[source 3](<https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w>)<br>[source 4](<https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp>)|
|2026-10-29 09:57:47 +0100|CircleCI|CircleCI cimg/php CI runtime image family|cimg/php:8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 (linux/amd64 and linux/arm64)|Fix|[source 1](<https://circleci.com/developer/images/image/cimg/php>)<br>[source 2](<https://github.com/CircleCI-Public/cimg-php/blob/main/README.md>)<br>[source 3](<https://github.com/CircleCI-Public/cimg-php/commit/76fe1c8bd2ec95f65faaa71159dadbfe23c264d5>)<br>[source 4](<https://hub.docker.com/v2/repositories/cimg/php/tags/8.2.35>)<br>[source 5](<https://hub.docker.com/v2/repositories/cimg/php/tags/8.3.36>)<br>[source 6](<https://hub.docker.com/v2/repositories/cimg/php/tags/8.4.27>)<br>[source 7](<https://hub.docker.com/v2/repositories/cimg/php/tags/8.5.12>)<br>[source 8](<https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w>)<br>[source 9](<https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp>)|
|2026-10-29 09:57:47 +0100|Composer / Satis maintainers|Satis official PHP container build recipe|composer/satis:latest with PHP 8.4.27 (2026-10-29 digest scope)|Fix|[source 1](<https://github.com/composer/satis/blob/main/Dockerfile>)<br>[source 2](<https://github.com/composer/satis/blob/main/README.md>)<br>[source 3](<https://hub.docker.com/v2/repositories/composer/satis/tags/latest>)<br>[source 4](<https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w>)<br>[source 5](<https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp>)|
|2026-10-29 09:57:47 +0100|Composer project / Docker Official Images|Composer default Docker runtime image|composer:2 with PHP 8.5.12 (2026-10-29 digest scope)|Fix|[source 1](<https://github.com/composer/docker/blob/a23788a1b4f65ad2dd090c3ee2a7ad9e35a7d9d1/latest/Dockerfile>)<br>[source 2](<https://github.com/docker-library/official-images/blob/master/library/composer>)<br>[source 3](<https://github.com/docker-library/docs/blob/master/composer/README.md>)<br>[source 4](<https://hub.docker.com/v2/repositories/library/composer/tags/2>)<br>[source 5](<https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w>)<br>[source 6](<https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp>)|
|2026-10-29 09:57:47 +0100|Docker Community / Docker Official Images, not WordPress upstream image ownership|WordPress Docker Official Image distribution|7.1.4-php8.4-apache: PHP 8.4.27 (2026-10-29 digest scope)|Fix|[source 1](<https://github.com/docker-library/wordpress/blob/master/Dockerfile.template>)<br>[source 2](<https://github.com/docker-library/wordpress>)<br>[source 3](<https://hub.docker.com/v2/repositories/library/wordpress/tags/7.1.4-php8.4-apache>)<br>[source 4](<https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w>)<br>[source 5](<https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp>)|

See the [full software status update history](software/changelog_software_list.md).

## Contributions welcome

If you have any additional information to share relevant to these PHP vulnerabilities, feel free to open a Pull request. New to this? [Read how to contribute in GitHub's documentation](https://docs.github.com/en/repositories/working-with-files/managing-files/editing-files#editing-files-in-another-users-repository).

For updates to the software list: our strong preference is to receive edits in the SPDX source files in `software/spdx/`. The Markdown list pages are generated automatically from those files. In case this proves too difficult: don't worry. We'll attempt to backport edits in the .md files to the SPDX source files, but without any guarantees. 

For a list of other contributions made by our community, see [Community contributions](COMMUNITY_CONTRIBUTIONS.MD).
