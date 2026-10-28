import unittest
from pathlib import Path

from tools import build_spdx_inventory as compiler
from tools import generate_software_list_from_spdx3 as generator


ROOT = Path(__file__).resolve().parents[1]
PREFIX = "urn:php2shell:inventory:"
CVES = ["CVE-2026-109618", "CVE-2026-109619"]


class VendorIssueInventoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.document, _, _ = compiler.compile_inventory(ROOT / "software" / "spdx")
        cls.nodes = {node.get("spdxId", node.get("@id")): node
                     for node in cls.document["@graph"]}
        _, cls.entries = generator.build_entry_map(cls.document)

    def test_clearpass_requires_the_released_php_hotfix(self):
        product = self.entries[PREFIX + "package:PHP-0751"]
        self.assertEqual([product[cve] for cve in CVES], ["Fix", "Fix"])
        for version in ("6.14.1", "6.11.16"):
            self.assertIn(version, product["version"])
        self.assertIn("hotfix", product["version"])
        self.assertIn("without the hotfix remain affected", product["notes"])
        self.assertIn("hpesbnw05171en_us", product["links"])

    def test_ontap_keeps_distinct_cve_assessments(self):
        product = self.entries[PREFIX + "package:PHP-0752"]
        self.assertEqual([product[cve] for cve in CVES], ["Fix", "Not vuln"])
        self.assertEqual(generator.combined_status(product, CVES), "Fix/Not vuln")
        self.assertIn("PHP jail", product["notes"])
        for release in ("9.15.1P20HF1", "9.16.1P16HF1", "9.17.1P11HF1",
                        "9.18.1P8HF1", "9.19.1P3HF1"):
            self.assertIn(release, product["version"])
        self.assertIn("NTAP-20261021-0021", product["links"])
        vex = self.nodes[PREFIX + "vex:CVE-2026-109618:fixedIn:php-0752-official-20261026"]
        self.assertIn("first fixed release", vex["security_actionStatement"])

    def test_sepm_fixed_builds_retain_report_provenance(self):
        product = self.entries[PREFIX + "package:PHP-0731"]
        self.assertEqual([product[cve] for cve in CVES], ["Fix", "Fix"])
        self.assertEqual(product["version"], "14.3.27716.10000 / 14.4.494.0000")
        self.assertIn("maintainer accepts issue #30", product["notes"])
        self.assertIn("not independently verified", product["notes"])
        self.assertIn("older releases", product["notes"])
        self.assertIn("/39421", product["links"])
        self.assertIn("https://github.com/NCSC-NL/php2shell/issues/30", product["links"])
        for cve in CVES:
            vex = self.nodes[PREFIX + f"vex:{cve}:fixedIn:php-0731-maintainer-20261023"]
            self.assertEqual(vex["to"], [PREFIX + "package:PHP-0731"])

    def test_cleo_streem_fix_keeps_pull_request_provenance(self):
        product = self.entries[PREFIX + "package:PHP-0757"]
        self.assertEqual([product[cve] for cve in CVES], ["Fix", "Fix"])
        self.assertEqual(product["version"], "Patch available by mail; fixed release not publicly stated")
        self.assertIn("Fix available by mail according to maintainer-accepted PR #41", product["notes"])
        self.assertIn("no public fixed build was independently verified", product["notes"])
        self.assertIn("https://github.com/NCSC-NL/php2shell/pull/41", product["links"])
        self.assertIn("Cleo-Streem-Release-Notes", product["links"])
        for cve in CVES:
            vex = self.nodes[PREFIX + f"vex:{cve}:fixedIn:php-0757-maintainer-20261027"]
            self.assertEqual(vex["to"], [PREFIX + "package:PHP-0757"])

    def test_securepoint_fix_keeps_issue_and_pull_request_provenance(self):
        product = self.entries[PREFIX + "package:PHP-0675"]
        self.assertEqual([product[cve] for cve in CVES], ["Fix", "Fix"])
        self.assertEqual(
            product["version"],
            "Patched before 2026-10-22 inventory entry; fixed release not publicly stated",
        )
        self.assertIn("issue #58", product["notes"])
        self.assertIn("PR #10", product["notes"])
        self.assertIn("no public fixed build was independently verified", product["notes"])
        self.assertIn("https://github.com/NCSC-NL/php2shell/issues/58", product["links"])
        self.assertIn("https://github.com/NCSC-NL/php2shell/pull/10", product["links"])
        for cve in CVES:
            vex = self.nodes[PREFIX + f"vex:{cve}:fixedIn:php-0675-maintainer-20261028"]
            self.assertEqual(vex["to"], [PREFIX + "package:PHP-0675"])

    def test_palo_alto_fix_tracks_current_etas_and_exploitation(self):
        for identifier in ("PHP-0623", "PHP-0625"):
            with self.subTest(identifier=identifier):
                product = self.entries[PREFIX + "package:" + identifier]
                self.assertEqual([product[cve] for cve in CVES], ["Fix", "Fix"])
                self.assertIn("ETA 2026-10-29", product["version"])
                self.assertIn("ETA 2026-10-30", product["version"])
                self.assertIn("active exploitation", product["notes"])
                self.assertIn("management web interface", product["notes"])
                self.assertNotIn("No known malicious exploitation", product["notes"])
                self.assertIn("CVE-2026-109618", product["links"])
        for cve in CVES:
            vex = self.nodes[PREFIX + f"vex:{cve}:fixedIn:paloalto-panos-panorama-20261028"]
            self.assertEqual(vex["to"], [PREFIX + "package:PHP-0623", PREFIX + "package:PHP-0625"])
            self.assertIn("still lists ETAs", vex["security_actionStatement"])

    def test_netscaler_fix_keeps_release_scope_and_management_boundary(self):
        product = self.entries[PREFIX + "package:PHP-0624"]
        self.assertEqual([product[cve] for cve in CVES], ["Fix", "Fix"])
        for release in ("14.1-73.49", "13.1-64.32", "13.1.37.286"):
            self.assertIn(release, product["version"])
        self.assertIn("earlier builds impacted", product["version"])
        self.assertIn("PHP-based management access", product["notes"])
        self.assertIn("NetScaler Console", product["notes"])
        self.assertIn("CTX697263", product["links"])
        for cve in CVES:
            vex = self.nodes[PREFIX + f"vex:{cve}:fixedIn:netscaler-management-20261027"]
            self.assertEqual(vex["to"], [PREFIX + "package:PHP-0624"])

    def test_broadcom_products_keep_independent_vendor_assessments(self):
        carbon_black = self.entries[PREFIX + "package:PHP-0730"]
        self.assertEqual(carbon_black["version"], "Broadcom ESG advisory 39404 affected product scope")
        self.assertNotIn("/39421", carbon_black["links"])
        self.assertNotIn("/issues/30", carbon_black["links"])
        for identifier, status in (
            ("PHP-0730", "Vulnerable"),
            ("PHP-0732", "Not vuln"),
            ("PHP-0733", "Not vuln"),
            ("PHP-0755", "Vulnerable"),
            ("PHP-0756", "Investigation"),
        ):
            with self.subTest(identifier=identifier):
                product = self.entries[PREFIX + "package:" + identifier]
                self.assertEqual([product[cve] for cve in CVES], [status, status])
        for cve in CVES:
            vex = self.nodes[PREFIX + f"vex:{cve}:affects:broadcom-esg-39404-20261022"]
            self.assertEqual(vex["to"], [PREFIX + "package:PHP-0730"])
            spanva = self.nodes[PREFIX + f"vex:{cve}:affects:php-0755-official-20261027"]
            self.assertEqual(spanva["to"], [PREFIX + "package:PHP-0755"])
            casma = self.nodes[PREFIX + f"vex:{cve}:underInvestigationFor:php-0756-official-20261027"]
            self.assertEqual(casma["to"], [PREFIX + "package:PHP-0756"])

    def test_new_products_have_unique_identity_and_php_dependencies(self):
        for identifier, supplier, name in (
            ("PHP-0751", "Hewlett Packard Enterprise", "HPE Networking ClearPass Policy Manager"),
            ("PHP-0752", "NetApp", "ONTAP 9"),
            ("PHP-0757", "Cleo", "Cleo Streem (Streem Print)"),
        ):
            with self.subTest(identifier=identifier):
                matches = [entry for entry in self.entries.values()
                           if entry["supplier"] == supplier and entry["product"] == name]
                self.assertEqual(len(matches), 1)
                relationship = self.nodes[PREFIX + "relationship:" + identifier]
                self.assertEqual(relationship["from"], PREFIX + "package:" + identifier)
                self.assertEqual(relationship["relationshipType"], "dependsOn")
                self.assertEqual(relationship["to"], [PREFIX + "package:PHP-0037"])


if __name__ == "__main__":
    unittest.main()
