#!/usr/bin/env python3
"""Generate alphabetized Markdown software lists from an SPDX 3 inventory."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import string
import subprocess
import sys
import unicodedata
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any

TITLE = "List of software with PHP dependency potentially affected by php2shell CVEs"
UPDATES_TITLE = "Software product status update history"
CHANGELOG_FILENAME = "changelog_software_list.md"
README_UPDATES_HEADING = "## Latest software status updates"
README_LEGACY_TIMESTAMP_PREFIX = "Readme last significant change:"
README_OPERATIONAL_TIMESTAMP_PREFIX = "Operational information last significant change:"
README_SOFTWARE_TIMESTAMP_PREFIX = "Software list last status update:"
HISTORY_DATE_TIME_FORMAT = "YYYY-MM-DD HH:MM:SS +/-HHMM"
BUCKETS = ["0-9", *string.ascii_uppercase]
DEFAULT_SPDX_DIR = Path("software") / "spdx"
VEX_STATUS_MAP = {
    "underInvestigationFor": "Investigation",
    "affects": "Vulnerable",
    "fixedIn": "Fix",
    "doesNotAffect": "Not vuln",
}


class GenerationError(ValueError):
    """Raised when an SPDX document cannot be rendered safely."""


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate alphabetized Markdown software lists from SPDX 3 JSON.",
    )
    parser.add_argument(
        "spdx_filename",
        type=Path,
        help="SPDX filename in software/spdx, or a path to an SPDX 3 JSON document",
    )
    parser.add_argument(
        "-o",
        "--output-dir",
        type=Path,
        default=Path("software"),
        help="Output directory. Default: software",
    )
    parser.add_argument(
        "--update-history",
        action="store_true",
        help=f"Also regenerate {CHANGELOG_FILENAME} from Git history.",
    )
    parser.add_argument(
        "--update-readme",
        action="store_true",
        help="Also refresh the root README latest software status table and timestamp.",
    )
    parser.add_argument(
        "--history-ref",
        default="HEAD",
        help="Git revision for mainline status history; use origin/main when updating a PR branch.",
    )
    return parser.parse_args(argv)


def resolve_spdx_path(spdx_filename: Path) -> Path:
    if spdx_filename.is_absolute() or spdx_filename.parent != Path(".") or spdx_filename.exists():
        return spdx_filename
    return DEFAULT_SPDX_DIR / spdx_filename


def load_json(path: Path) -> dict[str, Any]:
    try:
        with path.open("r", encoding="utf-8-sig") as handle:
            data = json.load(handle)
    except FileNotFoundError as exc:
        raise GenerationError(f"Input file does not exist: {path}") from exc
    except json.JSONDecodeError as exc:
        raise GenerationError(f"Input file is not valid JSON: {exc}") from exc

    if not isinstance(data, dict) or not isinstance(data.get("@graph"), list):
        raise GenerationError("Expected an SPDX JSON object with an '@graph' array.")
    return data


def raw_text(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        value = value.strip()
        return value or None
    return str(value)


def ascii_text(value: Any) -> str:
    value_text = raw_text(value) or ""
    replacements = {
        "\u00a0": " ",
        "\u2013": "-",
        "\u2014": "-",
        "\u2018": "'",
        "\u2019": "'",
        "\u201c": '"',
        "\u201d": '"',
        "\u2192": "->",
    }
    for source, replacement in replacements.items():
        value_text = value_text.replace(source, replacement)
    return unicodedata.normalize("NFKD", value_text).encode("ascii", "ignore").decode("ascii")


def markdown_cell(value: Any) -> str:
    value_text = ascii_text(value)
    value_text = value_text.replace("\\", "\\\\")
    value_text = value_text.replace("|", "\\|")
    value_text = re.sub(r"\r?\n+", "<br>", value_text)
    return value_text.strip()


def markdown_link(label: str, url: str) -> str:
    return f"[{markdown_cell(label)}](<{ascii_text(url)}>)"


def markdown_relative_link(label: str, path: str) -> str:
    return f"[{markdown_cell(label)}]({ascii_text(path)})"


def graph_by_type(graph: list[dict[str, Any]], element_type: str) -> list[dict[str, Any]]:
    return [element for element in graph if element.get("type") == element_type]


def organization_names(graph: list[dict[str, Any]]) -> dict[str, str]:
    return {
        element["spdxId"]: raw_text(element.get("name")) or "Unknown"
        for element in graph_by_type(graph, "Organization")
        if raw_text(element.get("spdxId"))
    }


def vulnerability_ids(graph: list[dict[str, Any]]) -> dict[str, str]:
    vulnerabilities = {}
    for element in graph_by_type(graph, "security_Vulnerability"):
        spdx_id = raw_text(element.get("spdxId"))
        name = raw_text(element.get("name"))
        if spdx_id and name:
            vulnerabilities[spdx_id] = name
    return vulnerabilities


def package_statuses(
    graph: list[dict[str, Any]],
    vulnerability_names: dict[str, str],
) -> tuple[dict[str, dict[str, str]], dict[str, list[str]]]:
    statuses: defaultdict[str, dict[str, str]] = defaultdict(dict)
    notes: defaultdict[str, list[str]] = defaultdict(list)

    for element in graph:
        element_type = raw_text(element.get("type")) or ""
        if not element_type.startswith("security_Vex"):
            continue
        cve = vulnerability_names.get(raw_text(element.get("from")) or "")
        if not cve:
            continue
        relationship_type = raw_text(element.get("relationshipType")) or ""
        status = VEX_STATUS_MAP.get(relationship_type, relationship_type or "Unknown")
        status_note = raw_text(element.get("security_statusNotes"))
        for package_id in element.get("to") or []:
            existing = statuses[package_id].get(cve)
            if existing and existing != status:
                raise GenerationError(
                    f"Conflicting VEX statuses for {package_id} and {cve}: {existing} vs {status}"
                )
            statuses[package_id][cve] = status
            if status_note and status_note not in notes[package_id]:
                notes[package_id].append(status_note)

    return dict(statuses), dict(notes)


def external_links(package: dict[str, Any]) -> str:
    refs = package.get("externalRef") or []
    urls: list[str] = []
    notes: list[str] = []
    for ref in refs:
        if not isinstance(ref, dict):
            continue
        locators = ref.get("locator") or []
        if isinstance(locators, str):
            locators = [locators]
        has_locator = False
        for locator in locators:
            locator_text = raw_text(locator)
            if locator_text:
                has_locator = True
                if locator_text not in urls:
                    urls.append(locator_text)
        if not has_locator:
            comment = raw_text(ref.get("comment"))
            if comment and comment not in notes:
                notes.append(comment)

    if not urls and not notes:
        return ""
    rendered: list[str] = []
    if len(urls) == 1:
        rendered.append(markdown_link("source", urls[0]))
    else:
        rendered.extend(markdown_link(f"source {index}", url) for index, url in enumerate(urls, 1))
    rendered.extend(markdown_cell(note) for note in notes)
    return "<br>".join(rendered)


def package_notes(package: dict[str, Any], status_notes: list[str]) -> str:
    parts: list[str] = []
    if status_notes:
        parts.append("CVE assessment: " + "; ".join(status_notes))
    summary = raw_text(package.get("summary"))
    if summary:
        parts.append(summary)
    return markdown_cell("\n".join(parts))


def bucket_for_supplier(supplier: str) -> str:
    first = ascii_text(supplier)[:1].upper()
    if first in string.ascii_uppercase:
        return first
    return "0-9"


def build_entries(document: dict[str, Any]) -> tuple[list[str], dict[str, list[dict[str, str]]]]:
    cves, entries = build_entry_map(document)
    buckets: defaultdict[str, list[dict[str, str]]] = defaultdict(list)

    for entry in entries.values():
        buckets[bucket_for_supplier(entry["supplier"])].append(entry)

    for entries in buckets.values():
        entries.sort(key=lambda item: (item["supplier"].casefold(), item["product"].casefold()))
    return cves, dict(buckets)


def build_entry_map(document: dict[str, Any]) -> tuple[list[str], dict[str, dict[str, str]]]:
    graph = document["@graph"]
    orgs = organization_names(graph)
    vulnerabilities = vulnerability_ids(graph)
    cves = sorted(vulnerabilities.values())
    statuses, status_notes = package_statuses(graph, vulnerabilities)
    entries: dict[str, dict[str, str]] = {}

    for package in graph_by_type(graph, "software_Package"):
        package_id = raw_text(package.get("spdxId"))
        product = raw_text(package.get("name"))
        if not package_id or not product:
            raise GenerationError("Each software_Package must have 'spdxId' and 'name'.")
        supplier = orgs.get(raw_text(package.get("suppliedBy")) or "", "Unknown")
        entry = {
            "supplier": markdown_cell(supplier),
            "product": markdown_cell(product),
            "version": markdown_cell(package.get("software_packageVersion")),
            "notes": package_notes(package, status_notes.get(package_id, [])),
            "links": external_links(package),
        }
        for cve in cves:
            entry[cve] = markdown_cell(statuses.get(package_id, {}).get(cve, ""))
        entries[package_id] = entry
    return cves, entries


def navigation_line() -> str:
    links = [markdown_relative_link(bucket, f"software_list_{bucket.lower()}.md") for bucket in BUCKETS]
    return " ".join(links)


def table_header(cves: list[str], *, include_date_time: bool = False) -> list[str]:
    columns = [
        *(["Date and time"] if include_date_time else []),
        "Supplier",
        "Product",
        "Version (see Status)",
        *[f"Status {cve}" for cve in cves],
        "Notes",
        "Links",
    ]
    alignment = []
    if include_date_time:
        alignment.append(":------------------------")
    alignment.extend(
        [
            ":---------",
            ":--------",
            ":--------------------:",
            *[":----------------------:" for _ in cves],
            ":------",
            "------:",
        ]
    )
    return [
        "| " + " | ".join(columns) + " |",
        "|" + "|".join(alignment) + "|",
    ]


def table_row(entry: dict[str, str], cves: list[str], *, date_time: str | None = None) -> str:
    row = [
        *([markdown_cell(date_time)] if date_time is not None else []),
        entry["supplier"],
        entry["product"],
        entry["version"],
        *[entry.get(cve, "") for cve in cves],
        entry["notes"],
        entry["links"],
    ]
    return "|" + "|".join(row) + "|"


def render_index() -> str:
    return "\n".join(
        [
            f"# {TITLE}",
            "[About this list](README.md)",
            "",
            navigation_line(),
            "",
        ]
    )


def render_bucket(bucket: str, cves: list[str], entries: list[dict[str, str]]) -> str:
    lines = [
        f"# {TITLE}",
        "[About this list](README.md)",
        "",
        navigation_line(),
        "",
        f"### {bucket}",
        "",
        *table_header(cves),
    ]
    for entry in entries:
        lines.append(table_row(entry, cves))
    lines.append("")
    return "\n".join(lines)


def git_executable() -> str:
    git = shutil.which("git")
    if git:
        return git
    if os.name == "nt":
        candidates = [
            Path(os.environ.get("ProgramFiles", "C:/Program Files")) / "Git" / "cmd" / "git.exe",
            Path(os.environ.get("ProgramFiles(x86)", "C:/Program Files (x86)")) / "Git" / "cmd" / "git.exe",
        ]
        for candidate in candidates:
            if candidate.exists():
                return str(candidate)
    raise GenerationError(f"Git is required to generate {CHANGELOG_FILENAME} and README updates.")


def run_git(git: str, repo_root: Path, *args: str) -> str:
    result = subprocess.run(
        [git, "-C", str(repo_root), *args],
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    if result.returncode != 0:
        message = result.stderr.strip() or result.stdout.strip() or "unknown git error"
        raise GenerationError(f"Git command failed: {message}")
    return result.stdout


def repository_root(git: str) -> Path:
    start = Path(__file__).resolve().parents[1]
    return Path(run_git(git, start, "rev-parse", "--show-toplevel").strip())


def status_signature(entry: dict[str, str] | None, cves: list[str]) -> tuple[str, ...]:
    if entry is None:
        return tuple("" for _ in cves)
    return tuple(entry.get(cve, "") for cve in cves)


def status_changed_entries(
    previous: dict[str, dict[str, str]],
    current: dict[str, dict[str, str]],
    cves: list[str],
) -> list[dict[str, str]]:
    changed = [
        entry
        for package_id, entry in current.items()
        if status_signature(previous.get(package_id), cves) != status_signature(entry, cves)
        and any(entry.get(cve) for cve in cves)
    ]
    changed.sort(key=lambda item: (item["supplier"].casefold(), item["product"].casefold()))
    return changed


def parse_git_date(value: str) -> str:
    try:
        return datetime.fromisoformat(value).strftime("%Y-%m-%d %H:%M:%S %z")
    except ValueError:
        return value


def format_readme_timestamp(value: str | None) -> str:
    try:
        timestamp = datetime.fromisoformat(value) if value else datetime.now().astimezone()
    except ValueError:
        return value or ""
    timezone = {
        "+0100": "CET",
        "+0200": "CEST",
    }.get(timestamp.strftime("%z"), timestamp.strftime("%Z") or timestamp.strftime("%z"))
    return f"{timestamp.day} {timestamp.strftime('%B %Y %H:%M')} {timezone}"


def load_history_snapshot(git: str, repo_root: Path, commit: str, relative_spdx_path: str) -> dict[str, Any]:
    try:
        data = json.loads(run_git(git, repo_root, "show", f"{commit}:{relative_spdx_path}"))
    except json.JSONDecodeError as exc:
        raise GenerationError(f"Git snapshot {commit} is not valid JSON: {exc}") from exc
    if not isinstance(data, dict) or not isinstance(data.get("@graph"), list):
        raise GenerationError(f"Git snapshot {commit} is not an SPDX document with an '@graph' array.")
    return data


def build_status_history(
    document: dict[str, Any],
    spdx_path: Path,
    history_ref: str = "HEAD",
) -> tuple[list[str], list[dict[str, Any]]]:
    git = git_executable()
    repo_root = repository_root(git)
    try:
        relative_spdx_path = spdx_path.resolve().relative_to(repo_root).as_posix()
    except ValueError as exc:
        raise GenerationError("SPDX file must be inside the Git repository to generate update history.") from exc

    current_cves, current_entries = build_entry_map(document)
    log_output = run_git(
        git,
        repo_root,
        "log",
        "--first-parent",
        "--reverse",
        "--format=%H%x09%aI",
        history_ref,
        "--",
        relative_spdx_path,
    )
    events: list[dict[str, Any]] = []
    previous_entries: dict[str, dict[str, str]] = {}
    for line in log_output.splitlines():
        if not line:
            continue
        commit, authored_at = line.split("\t", 1)
        _, entries = build_entry_map(load_history_snapshot(git, repo_root, commit, relative_spdx_path))
        changed = status_changed_entries(previous_entries, entries, current_cves)
        if changed:
            events.append(
                {
                    "date_time": parse_git_date(authored_at),
                    "authored_at": authored_at,
                    "entries": changed,
                }
            )
        previous_entries = entries

    pending = status_changed_entries(previous_entries, current_entries, current_cves)
    if pending:
        authored_at = datetime.now().astimezone().isoformat(timespec="seconds")
        events.append(
            {
                "date_time": parse_git_date(authored_at),
                "authored_at": authored_at,
                "entries": pending,
            }
        )
    return current_cves, events


def history_rows(events: list[dict[str, Any]]) -> list[tuple[str, dict[str, str]]]:
    rows: list[tuple[str, dict[str, str]]] = []
    for event in reversed(events):
        date_time = event["date_time"]
        rows.extend((date_time, entry) for entry in event["entries"])
    return rows


def render_updates_history(cves: list[str], events: list[dict[str, Any]]) -> str:
    lines = [
        f"# {UPDATES_TITLE}",
        "[About this list](README.md)",
        "",
        "This file is generated from status-changing SPDX snapshots in the repository mainline Git history.",
        f"Rows are ordered newest first. The `Date and time` column uses `{HISTORY_DATE_TIME_FORMAT}`.",
        "",
        *table_header(cves, include_date_time=True),
    ]
    lines.extend(table_row(entry, cves, date_time=date_time) for date_time, entry in history_rows(events))
    lines.append("")
    return "\n".join(lines)


def latest_update_entries(events: list[dict[str, Any]], limit: int = 5) -> list[tuple[str, dict[str, str]]]:
    return history_rows(events)[:limit]


def render_readme_updates(cves: list[str], entries: list[tuple[str, dict[str, str]]]) -> str:
    lines = [README_UPDATES_HEADING, "", *table_header(cves, include_date_time=True)]
    lines.extend(table_row(entry, cves, date_time=date_time) for date_time, entry in entries)
    lines.extend(["", f"See the [full software status update history](software/{CHANGELOG_FILENAME})."])
    return "\n".join(lines)


def write_generated_text(path: Path, content: str, default_newline: str = "\n") -> None:
    existing = path.read_bytes() if path.exists() else b""
    newline = "\r\n" if b"\r\n" in existing else default_newline
    normalized = content.replace("\r\n", "\n")
    rendered = normalized.replace("\n", newline).encode("utf-8")
    if rendered != existing:
        path.write_bytes(rendered)


def write_readme_updates(
    repo_root: Path,
    cves: list[str],
    entries: list[tuple[str, dict[str, str]]],
    software_updated_at: str | None,
) -> None:
    readme_path = repo_root / "README.md"
    if not readme_path.exists():
        raise GenerationError(f"README does not exist: {readme_path}")
    raw = readme_path.read_bytes()
    text = raw.decode("utf-8").replace("\r\n", "\n")
    section = render_readme_updates(cves, entries)
    pattern = re.compile(
        rf"^{re.escape(README_UPDATES_HEADING)}\r?\n.*?(?=^## |\Z)",
        re.MULTILINE | re.DOTALL,
    )
    if pattern.search(text):
        updated = pattern.sub(section + "\n\n", text, count=1)
    else:
        marker = "## Contributions welcome"
        if marker not in text:
            raise GenerationError(f"README is missing expected heading: {marker}")
        updated = text.replace(marker, section + "\n\n" + marker, 1)

    if updated != text or README_SOFTWARE_TIMESTAMP_PREFIX not in updated:
        timestamp = format_readme_timestamp(software_updated_at)
        if README_LEGACY_TIMESTAMP_PREFIX in updated:
            updated = updated.replace(
                README_LEGACY_TIMESTAMP_PREFIX,
                README_OPERATIONAL_TIMESTAMP_PREFIX,
                1,
            )
        software_timestamp = f"{README_SOFTWARE_TIMESTAMP_PREFIX} {timestamp}"
        timestamp_pattern = re.compile(
            rf"^{re.escape(README_SOFTWARE_TIMESTAMP_PREFIX)}.*$",
            re.MULTILINE,
        )
        if timestamp_pattern.search(updated):
            updated = timestamp_pattern.sub(software_timestamp, updated, count=1)
        else:
            operational_pattern = re.compile(
                rf"^({re.escape(README_OPERATIONAL_TIMESTAMP_PREFIX)}.*)$",
                re.MULTILINE,
            )
            if not operational_pattern.search(updated):
                raise GenerationError(
                    "README is missing an operational timestamp line for software timestamp insertion."
                )
            updated = operational_pattern.sub(rf"\1\n{software_timestamp}", updated, count=1)
    write_generated_text(readme_path, updated)


def write_lists(document: dict[str, Any], output_dir: Path) -> tuple[int, dict[str, int]]:
    cves, buckets = build_entries(document)
    output_dir.mkdir(parents=True, exist_ok=True)
    write_generated_text(output_dir / "software_list.md", render_index())

    counts: dict[str, int] = {}
    for bucket in BUCKETS:
        entries = buckets.get(bucket, [])
        counts[bucket] = len(entries)
        path = output_dir / f"software_list_{bucket.lower()}.md"
        write_generated_text(path, render_bucket(bucket, cves, entries))
    return sum(counts.values()), counts


def write_optional_outputs(
    document: dict[str, Any],
    spdx_path: Path,
    output_dir: Path,
    *,
    update_history: bool,
    update_readme: bool,
    history_ref: str = "HEAD",
) -> int:
    if not update_history and not update_readme:
        return 0
    history_cves, events = build_status_history(document, spdx_path, history_ref)
    if update_history:
        write_generated_text(output_dir / CHANGELOG_FILENAME, render_updates_history(history_cves, events))
    if update_readme:
        latest_event = events[-1] if events else {}
        write_readme_updates(
            repository_root(git_executable()),
            history_cves,
            latest_update_entries(events),
            latest_event.get("authored_at"),
        )
    return sum(len(event["entries"]) for event in events)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    try:
        spdx_path = resolve_spdx_path(args.spdx_filename)
        document = load_json(spdx_path)
        total, counts = write_lists(document, args.output_dir)
        updates = write_optional_outputs(
            document,
            spdx_path,
            args.output_dir,
            update_history=args.update_history,
            update_readme=args.update_readme,
            history_ref=args.history_ref,
        )
    except GenerationError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    populated = ", ".join(f"{bucket}={count}" for bucket, count in counts.items() if count)
    message = f"Wrote {total} software rows to {args.output_dir}."
    if args.update_history:
        message += f" Updated {updates} status history rows."
    if args.update_readme:
        message += " Updated README latest software status table."
    print(f"{message} Populated buckets: {populated}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
