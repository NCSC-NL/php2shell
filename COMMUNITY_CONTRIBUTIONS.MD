> [!WARNING]
> **COMMUNITY CONTRIBUTIONS - USE AT YOUR OWN RISK**
>
> These tools and tips are contributions from the community. **NCSC-NL has not verified or tested them, does not endorse them, and has no knowledge of the tools' internal workings.** Inclusion in this document does not imply approval or a recommendation by NCSC-NL.
>
> **NCSC-NL accepts no responsibility or liability for these contributions or for any damage, loss, security incident, or other consequences resulting from their use.** You are responsible for independently assessing their safety and suitability before use.

# Community contributions

This catalog records community tools, tips, guides, and reference resources submitted through open pull requests and issues in [NCSC-NL/php2shell](https://github.com/NCSC-NL/php2shell). The open submissions were reviewed on **28 October 2026**: seven pull requests and four issues, of which five pull requests and three issues proposed resources included below. Submissions concerned solely with software inventory changes are outside this catalog.

**Contributor** identifies the PR or issue author's GitHub username, which does not necessarily identify the tool's author or maintainer. Descriptions summarize the submissions and linked documentation; their functionality, effectiveness, and claims have not been independently validated. Listing a contribution does not mean that its source PR has been accepted. Links to proposed files use the reviewed commit, because those files may not exist on `main`.

## Runtime discovery and checks

| Contributor | Tool or tip name | Short description | Tool/project URL | Source PR/issue link |
| --- | --- | --- | --- | --- |
| [@andreysheva](https://github.com/andreysheva) | php2shell-doctor | Go CLI described as providing local PHP discovery, vendor-package fix comparisons, stale-worker detection, configuration and log checks, and lookup against this repository's SPDX inventory. | [Project](https://github.com/andreysheva/php2shell-doctor) | [PR #47](https://github.com/NCSC-NL/php2shell/pull/47) |
| [@adityaaravind](https://github.com/adityaaravind) | php2shell-check | Node.js CLI for checking local PHP, Docker images and containers, inventory files, and HTTP headers, with reports and a GitHub Action. Distinguishes CLI and PHP-FPM; headers alone cannot establish patch status. | [Project](https://github.com/adityaaravind/php2shell-check) | [PR #24](https://github.com/NCSC-NL/php2shell/pull/24) |
| [@KyleClouthier](https://github.com/KyleClouthier) | check-php.php | PHP script placed in a site's document root to display the web-serving runtime version and branch support status, then attempt self-deletion. Manual removal may be needed; a version string alone does not establish vendor backport status. | [Proposed script](https://github.com/NCSC-NL/php2shell/blob/9cfede38affaa9fb04f205ec69826c26f353af00/detection_mitigation/version_check/check-php.php) | \[[PR #9](https://github.com/NCSC-NL/php2shell/pull/9)\] |
| [@KyleClouthier](https://github.com/KyleClouthier) | PHP2Shell checker (simgen.dev) | External website check described as using public HTTP headers, cookies, and CMS fingerprints. Hidden or misleading signals can prevent identification of the actual PHP runtime or its patch status. | [Website](https://simgen.dev/php-patch-check/) | \[[PR #9](https://github.com/NCSC-NL/php2shell/pull/9)\] |

## Inventory and remediation tools

| Contributor | Tool or tip name | Short description | Tool/project URL | Source PR/issue link |
| --- | --- | --- | --- | --- |
| [@xbuddhi](https://github.com/xbuddhi) | php2shell-fix | Linux PHP inventory and remediation script covering distribution packages, control-panel installations, and custom builds. Remediation can upgrade packages, rebuild PHP, and restart services; installer and script defaults differ, so execution is not necessarily report-only. | [Project](https://github.com/xbuddhi/php2shell-fix) | [PR #15](https://github.com/NCSC-NL/php2shell/pull/15) |
| [@it-reinbek](https://github.com/it-reinbek) | PHP2Shell Auditor & Remediation Tool | Interactive Bash tool for host/container discovery, package and configuration checks, log inspection, and reporting. Remediation functions can change PHP/systemd settings and stop and recreate Docker stacks. | [php2shell-auditor project](https://github.com/it-reinbek/php2shell-auditor) | [Issue #45](https://github.com/NCSC-NL/php2shell/issues/45) |

## Verification and operational guidance

| Contributor | Tool or tip name | Short description | Tool/project URL | Source PR/issue link |
| --- | --- | --- | --- | --- |
| [@adityaaravind](https://github.com/adityaaravind) | Scanning and verification | Proposed guide covering vendor backports, differences between CLI and web-serving PHP, unreliable response headers, container drift, stale workers, and verification of the configuration used by the serving runtime. | [Proposed guide](https://github.com/NCSC-NL/php2shell/blob/538966c50eb670df0c8063f9d3eb8300846397da/detection_mitigation/scanning/README.md) | [PR #24](https://github.com/NCSC-NL/php2shell/pull/24) |
| [@xbuddhi](https://github.com/xbuddhi) | Server-wide PHP inventory | Proposed Linux inventory guide for finding distribution, control-panel, and custom PHP builds; checking package ownership and backport evidence; and identifying workers still using old binaries. Containers require separate checks, and incomplete discovery is not proof of absence. | [Proposed guide](https://github.com/NCSC-NL/php2shell/blob/a16848f8a2d3cf3b81cb2c778bdb1f39b2129ea5/detection_mitigation/server-inventory/README.md) | [PR #15](https://github.com/NCSC-NL/php2shell/pull/15) |
| [@mazzma12](https://github.com/mazzma12) | CrowdSec virtual-patching setup guide | CrowdSec AppSec/WAF deployment and rule-update guidance for the two PHP2Shell CVEs. Rule maintenance differs by deployment type; filtering is an interim mitigation and does not repair the PHP runtime. | [Setup guide](https://www.crowdsec.net/blog/php2shell-virtual-patching) | [Issue #57](https://github.com/NCSC-NL/php2shell/issues/57) |

## Compensating controls

These submissions propose interim filtering controls. Their coverage depends on the deployment and request path; they do not replace PHP security updates.

| Contributor | Tool or tip name | Short description | Tool/project URL | Source PR/issue link |
| --- | --- | --- | --- | --- |
| [@Taz1920](https://github.com/Taz1920) | PHP CanaryWall | Reverse proxy combining upload-progress filtering and request replay through isolated PHP canaries, proposed for older PHP deployments. Its documentation notes gaps for silent exploitation, attacks spanning multiple requests, and trigger paths outside upload progress. | [Project](https://github.com/Taz1920/PHP-Canarywall) | [PR #27](https://github.com/NCSC-NL/php2shell/pull/27) |
| [@mazzma12](https://github.com/mazzma12) | CrowdSec WAF rule: CVE-2026-109618 | Tentative rule targeting deeply nested multipart fields and excessive file parts associated with memory-exhaustion attempts. Uses heuristic thresholds that can also block legitimate requests; only covers traffic passing through the WAF. | [Rule on CrowdSec Hub](https://app.crowdsec.net/hub/author/crowdsecurity/waf-rules/vpatch-CVE-2026-109618) | [Issue #57](https://github.com/NCSC-NL/php2shell/issues/57) |
| [@mazzma12](https://github.com/mazzma12) | CrowdSec WAF rule: CVE-2026-109619 | Tentative rule inspecting raw multipart requests for the default PHP_SESSION_UPLOAD_PROGRESS field. Its documented scope excludes renamed progress fields and other trigger paths; only covers traffic passing through the WAF. | [Rule on CrowdSec Hub](https://app.crowdsec.net/hub/author/crowdsecurity/waf-rules/vpatch-CVE-2026-109619) | [Issue #57](https://github.com/NCSC-NL/php2shell/issues/57) |

## Package and hosting reference tables

| Contributor | Tool or tip name | Short description | Tool/project URL | Source PR/issue link |
| --- | --- | --- | --- | --- |
| [@littleblackone](https://github.com/littleblackone) | Fixed PHP versions by distribution | Independent package-version reference with vendor advisory links and a browser-side version comparison. It is not a host scanner; comparing a supplied version does not verify the deployed runtime. Check the linked vendor advisory for current evidence. | [Fixed-version reference](https://php2shellcheck.com/fixed-versions/) | [Issue #23](https://github.com/NCSC-NL/php2shell/issues/23) |
| [@littleblackone](https://github.com/littleblackone) | Hosting provider patch status | Independent table of hosting, control-panel, and CDN statements, with source links and recorded check times. A provider-wide statement may not establish the status of an individual service; consult the provider's current notice. | [Hosting-status reference](https://php2shellcheck.com/hosting-status/) | [Issue #23](https://github.com/NCSC-NL/php2shell/issues/23) |

## Threat activity and telemetry

The contributor of the CrowdSec resources, @mazzma12, disclosed employment at CrowdSec and authorship of the linked report in issue #57.

| Contributor | Tool or tip name | Short description | Tool/project URL | Source PR/issue link |
| --- | --- | --- | --- | --- |
| [@mazzma12](https://github.com/mazzma12) | CrowdSec PHP2Shell telemetry report | Report on request patterns observed and blocked by CrowdSec sensors during 21-25 October 2026. Blocked requests indicate attempts, not confirmed compromise; sensor coverage is a sample, and an IP address does not identify a distinct actor. | [Report](https://www.crowdsec.net/vulntracking-report/cve-2026-109618-php2shell-no-mass-exploitation-yet) | [Issue #57](https://github.com/NCSC-NL/php2shell/issues/57) |
| [@mazzma12](https://github.com/mazzma12) | CrowdSec Live Exploit Tracker | Dashboard for CrowdSec observations associated with CVE-2026-109618. Counts and assessments change over time and reflect the provider's visibility; they are not a complete measure of exploitation or confirmed compromises. | [CVE tracker](https://tracker.crowdsec.net/cves/CVE-2026-109618) | [Issue #57](https://github.com/NCSC-NL/php2shell/issues/57) |

---

> [!WARNING]
> **COMMUNITY CONTRIBUTIONS - USE AT YOUR OWN RISK**
>
> These tools and tips are contributions from the community. **NCSC-NL has not verified or tested them, does not endorse them, and has no knowledge of the tools' internal workings.** Inclusion in this document does not imply approval or a recommendation by NCSC-NL.
>
> **NCSC-NL accepts no responsibility or liability for these contributions or for any damage, loss, security incident, or other consequences resulting from their use.** You are responsible for independently assessing their safety and suitability before use.
