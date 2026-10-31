# GetPageSpeed: HTML modification and remote enforcement concerns

> [!CAUTION]
> **Review GetPageSpeed runtime behaviour before installing its PHP security backports.**
> The vendor documents HTML modification in Everpatch PHP and separate NGINX enforcement that can block service. Security patch availability alone does not establish that a package is safe to deploy.

Reviewed on 31 October 2026. This notice is maintained by the owner of this fork and is proposed for upstream review. The concern is based on the vendor's published documentation.

## Documented behaviour

1. **Everpatch PHP:** the Terms of Service permit appending visible notices to served HTML after an evaluation period. The stated commercial production terms cover the EL7 and Debian/Ubuntu PHP packages and require Ultra or higher.
2. **NGINX licensing module:** `soft` logs warnings, `footer` appends a notice and `hard` returns HTTP 503. The documentation says a response from the licensing backend can override the local enforcement setting until restart. The same page labels usage reporting as not yet implemented, so the actual behaviour of a specific build requires verification.
3. **Pricing:** the PHP2Shell page advertises GetPageSpeed Ultra at $500 per year for commercial use on up to 10 servers. This is the published subscription price, not an observed ransom or incident-specific restoration demand.

These policies create an operational concern about content integrity, service availability and administrator control when choosing a security backport.

## Exact scope

The PHP package previously considered was **8.0.30-25.el7**, listed in inventory entry **PHP-0753**. Entry **PHP-0758** covers the vendor's Debian/Ubuntu PHP packages and is also relevant to the stated Everpatch terms.

We have not established that the PHP package contains the NGINX licensing module or its enforcement behaviour. No vendor binary was installed or executed for this review. The available evidence supports a warning about documented potentially unwanted functionality. It does not establish a Trojan classification or an observed payment demand to restore a particular site.

## Requested inventory treatment

Add a prominent warning to these vendor entries and keep their links inactive in the rendered inventory and history during review. Preserve original SPDX source URLs and existing PHP CVE assessments for traceability. The `Fix` status is scoped to CVE-2026-109618 and CVE-2026-109619. It is not a package-safety certification or an NCSC recommendation to install the vendor's products.

## Primary references, deliberately inactive

- Everpatch PHP terms: `hxxps://www.getpagespeed[.]com/terms`, section "Free Channels and Everpatch PHP".
- NGINX enforcement: `hxxps://nginx-extras.getpagespeed[.]com/modules/gps-license/`, directive `gps_license_enforcement` and the adjacent reporting notes.
- PHP2Shell package offering and Ultra price: `hxxps://www.getpagespeed[.]com/php2shell`, EOL PHP packages section.
