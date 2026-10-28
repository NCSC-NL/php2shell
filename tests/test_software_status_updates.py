import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tools import generate_software_list_from_spdx3 as generator


CVES = ["CVE-2026-109618", "CVE-2026-109619"]


def entry(product, statuses=("Fix", "Fix")):
    return {
        "supplier": "Example supplier",
        "product": product,
        "version": "1.2.3",
        "notes": "Only the named image is fixed; running deployments are unverified.",
        "links": "[source](<https://example.org/advisory>)",
        **dict(zip(CVES, statuses)),
    }


def table_lines(text):
    return [line for line in text.splitlines() if line.startswith("|")]


class SoftwareStatusUpdatesTests(unittest.TestCase):
    def test_readme_merges_statuses_in_cve_order_and_omits_notes(self):
        date_time = "2026-10-23 10:00:00 +0200"
        cases = (
            (("Fix", "Fix"), "Fix"),
            (("Vulnerable", "Vulnerable"), "Vulnerable"),
            (("Vulnerable", "Not vuln"), "Vulnerable/Not vuln"),
            (("Fix", "Investigation"), "Fix/Investigation"),
            (("", "Not vuln"), "/Not vuln"),
        )
        for statuses, expected_status in cases:
            with self.subTest(statuses=statuses):
                product = entry("Scoped image", statuses)
                rendered = generator.render_readme_updates(CVES, [(date_time, product)])
                lines = table_lines(rendered)
                self.assertEqual(
                    [cell.strip() for cell in lines[0].split("|")[1:-1]],
                    ["Date and time", "Supplier", "Product", "Version (see Status)",
                     "Status CVE-2026-109618 / CVE-2026-109619", "Links"],
                )
                self.assertEqual(lines[2].split("|")[1:-1], [
                    date_time, product["supplier"], product["product"],
                    product["version"], expected_status, product["links"],
                ])
                self.assertNotIn(product["notes"], rendered)

    def test_full_history_retains_separate_status_columns_and_notes(self):
        date_time = "2026-10-23 10:00:00 +0200"
        product = entry("Scoped image", ("Vulnerable", "Not vuln"))
        rendered = generator.render_updates_history(
            CVES, [{"date_time": date_time, "entries": [product]}],
        )
        self.assertEqual(
            table_lines(rendered),
            generator.table_header(CVES, include_date_time=True)
            + [generator.table_row(product, CVES, date_time=date_time)],
        )
        self.assertIn(product["notes"], rendered)

    def test_readme_uses_first_five_history_rows_including_ties(self):
        events = [
            {"date_time": "2026-10-22 10:00:00 +0200", "entries": [entry("Old")]},
            {
                "date_time": "2026-10-23 10:00:00 +0200",
                "entries": [entry(f"New {index}") for index in range(6)],
            },
        ]
        latest = generator.latest_update_entries(events)
        self.assertEqual(len(latest), 5)
        self.assertEqual([row[1]["product"] for row in latest], [f"New {i}" for i in range(5)])
        readme_rows = table_lines(generator.render_readme_updates(CVES, latest))[2:]
        history_rows = table_lines(generator.render_updates_history(CVES, events))[2:]
        self.assertEqual(len(readme_rows), 5)
        self.assertEqual(
            [row.split("|")[1:5] for row in readme_rows],
            [row.split("|")[1:5] for row in history_rows[:5]],
        )

    def test_empty_updates_retain_schema_and_history_link(self):
        rendered = generator.render_readme_updates(CVES, [])
        self.assertEqual(table_lines(rendered), generator.readme_table_header(CVES))
        self.assertIn("(software/changelog_software_list.md)", rendered)

    def test_readme_insertion_preserves_surrounding_content_and_crlf(self):
        original = (
            "# Inventory\r\nOperational information: unchanged<br>\r\n"
            "## Repository contents\r\nKeep this text.\r\n\r\n"
            "## Contributions welcome\r\nKeep this too.\r\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            readme = root / "README.md"
            readme.write_bytes(original.encode("utf-8"))
            generator.write_readme_updates(root, CVES, [], "2026-10-23T10:00:00+02:00")
            updated = readme.read_bytes()
        text = updated.decode("utf-8")
        self.assertLess(text.index("## Repository contents"), text.index(generator.README_UPDATES_HEADING))
        self.assertLess(text.index(generator.README_UPDATES_HEADING), text.index("## Contributions welcome"))
        self.assertIn("Operational information: unchanged<br>\r\n", text)
        self.assertIn("Keep this text.\r\n", text)
        self.assertTrue(text.endswith("## Contributions welcome\r\nKeep this too.\r\n"))
        self.assertNotIn(b"\n", updated.replace(b"\r\n", b""))

    def test_optional_outputs_share_history_and_forward_mainline_ref(self):
        events = [{
            "date_time": "2026-10-23 10:00:00 +0200",
            "authored_at": "2026-10-23T10:00:00+02:00",
            "entries": [entry(f"Image {index}") for index in range(6)],
        }]
        document = {"@graph": []}
        spdx_path = Path("software/spdx/inventory.json")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "README.md").write_text(
                "# Inventory\nOperational information: unchanged<br>\n"
                "## Repository contents\n\n## Contributions welcome\n",
                encoding="utf-8",
            )
            with (
                patch.object(generator, "build_status_history", return_value=(CVES, events)) as history,
                patch.object(generator, "repository_root", return_value=root),
                patch.object(generator, "git_executable", return_value="git"),
            ):
                count = generator.write_optional_outputs(
                    document, spdx_path, root,
                    update_history=True, update_readme=True, history_ref="origin/main",
                )
            history.assert_called_once_with(document, spdx_path, "origin/main")
            self.assertEqual(count, 6)
            readme_rows = table_lines((root / "README.md").read_text(encoding="utf-8"))[2:]
            history_rows = table_lines(
                (root / generator.CHANGELOG_FILENAME).read_text(encoding="utf-8"),
            )[2:]
            self.assertEqual(len(readme_rows), 5)
            self.assertEqual(len(history_rows), 6)
            self.assertEqual(
                [row.split("|")[1:5] for row in readme_rows],
                [row.split("|")[1:5] for row in history_rows[:5]],
            )


if __name__ == "__main__":
    unittest.main()
