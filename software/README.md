# Overview of software potentially affected by php2shell

This directory contains an overview of software products that may be affected by CVE-2026-109618 and CVE-2026-109619. PHP's official advisory states that all PHP installations serving web requests are at risk and identifies PHP 8.5.12, 8.4.27, 8.3.36 and 8.2.35 as fixed upstream releases. Product entries should still be treated as investigation leads until they are backed by an upstream or vendor source, or by direct primary research scoped to a named product and runtime, because products may ship embedded runtimes, delayed rebuilds or vendor backports.

Please note that these vulnerabilities may also occur in custom PHP applications deployed within your organisation. Those occurrences are not registered in this overview.

## Software overview

The following status labels are in use:

| Status | Description |
| --- | --- |
| Investigation | The product may be affected and is being assessed. |
| Vulnerable | An upstream or vendor source, or direct primary research, confirms that the product is vulnerable in the stated scope. |
| Fix | An upstream or vendor source confirms that the listed version contains a fix. |
| Workaround | The product is vulnerable, but mitigation steps are available. |
| Not vuln | An upstream or vendor source confirms that the product is not vulnerable. |

The `Version` column in the software list relates to the status of the entry. For `Vulnerable`, it identifies known vulnerable versions when available. For `Fix`, it identifies the version in which the fix was introduced.

See [software_list.md](software_list.md) for the current list.

For upstream PHP remediation guidance, see the [official PHP security advisory](https://www.php.net/archive/2026.php#2026-10-21-5).

The source of truth for this overview is the JSON fragments in [spdx/segments](spdx/segments/) and [spdx/shared](spdx/shared/). Run `python tools/build_spdx_inventory.py` from the repository root to compile every source JSON into `spdx/PHP_Downstream_Inventory.spdx3.json`. See [SPDX source maintenance](spdx/README.md) for the categories and editing workflow. The alphabetized Markdown pages are generated automatically from the compiled inventory using the tooling in [../tools](../tools/). Status values in the current list are derived from the VEX assessment relationships in the SPDX document.

> **Disclaimer:** No guarantees are made regarding the completeness or accuracy of this inventory. Verify entries against upstream or vendor sources before acting on them.

[0-9](software_list_0-9.md) [A](software_list_a.md) [B](software_list_b.md) [C](software_list_c.md) [D](software_list_d.md) [E](software_list_e.md) [F](software_list_f.md) [G](software_list_g.md) [H](software_list_h.md) [I](software_list_i.md) [J](software_list_j.md) [K](software_list_k.md) [L](software_list_l.md) [M](software_list_m.md) [N](software_list_n.md) [O](software_list_o.md) [P](software_list_p.md) [Q](software_list_q.md) [R](software_list_r.md) [S](software_list_s.md) [T](software_list_t.md) [U](software_list_u.md) [V](software_list_v.md) [W](software_list_w.md) [X](software_list_x.md) [Y](software_list_y.md) [Z](software_list_z.md)
