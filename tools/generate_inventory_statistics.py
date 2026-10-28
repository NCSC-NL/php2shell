#!/usr/bin/env python3
"""Generate README statistics and stacked bars for recent SPDX update days."""

from __future__ import annotations

import argparse
import io
import json
import re
import sys
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

from generate_software_list_from_spdx3 import (
    GenerationError,
    build_entry_map,
    ensure_readme_links,
    git_executable,
    load_history_snapshot,
    load_json,
    repository_root,
    run_git,
    write_generated_text,
)

SPDX_PATH = "software/spdx/PHP_Downstream_Inventory.spdx3.json"
OUTPUT_DIR = "software/statistics"
HEADING = "## Software inventory statistics"
BEGIN = "<!-- inventory-statistics:start -->"
END = "<!-- inventory-statistics:end -->"
SUMMARY_BEGIN = "<!-- inventory-statistics:summary:start -->"
SUMMARY_END = "<!-- inventory-statistics:summary:end -->"
LABELS = {
    "tracked": "Products tracked",
    "fixed": "Fixed",
    "vulnerable": "Vulnerable",
    "investigation": "Under investigation",
    "not_affected": "Not affected",
    "unknown": "Unassessed / unknown",
}
COLORS = {
    "vulnerable": "#d74758",
    "fixed": "#278f6b",
    "investigation": "#8190a8",
    "not_affected": "#4389c9",
    "unknown": "#a77abb",
}
STATUS_KEYS = {
    "Fix": "fixed",
    "Vulnerable": "vulnerable",
    "Investigation": "investigation",
    "Not vuln": "not_affected",
}


def product_status(statuses: list[str]) -> str:
    """Partition products once, without treating partially resolved CVEs as fixed."""
    if "Vulnerable" in statuses:
        return "vulnerable"
    if "Investigation" in statuses:
        return "investigation"
    if not statuses or any(status not in STATUS_KEYS for status in statuses):
        return "unknown"
    if "Fix" in statuses:
        return "fixed"
    return "not_affected"


def count_inventory(document: dict[str, Any], cves: list[str]) -> dict[str, Any]:
    _, entries = build_entry_map(document)
    counts = dict.fromkeys(LABELS, 0)
    counts["tracked"] = len(entries)
    by_cve = {cve: dict.fromkeys(list(LABELS)[1:], 0) for cve in cves}
    for entry in entries.values():
        counts[product_status([entry.get(cve, "") for cve in cves])] += 1
        for cve in cves:
            by_cve[cve][STATUS_KEYS.get(entry.get(cve, ""), "unknown")] += 1
    return {"counts": counts, "by_cve": by_cve}


def update_day_snapshots(
    commits: list[tuple[str, date]], end_date: date, days: int
) -> list[tuple[date, str]]:
    """Select the last mainline snapshot on each of the latest update dates."""
    by_date = {}
    for commit, committed_on in commits:
        if committed_on <= end_date:
            by_date[committed_on] = commit
    return sorted(by_date.items())[-days:]


def build_statistics(
    repo_root: Path, document: dict[str, Any], history_ref: str, days: int, today: date
) -> dict[str, Any]:
    git = git_executable()
    if run_git(git, repo_root, "rev-parse", "--is-shallow-repository").strip() == "true":
        raise GenerationError("Statistics require full Git history; fetch with --unshallow first.")
    # Resolve once so concurrent branch updates cannot change the selected history.
    revision = run_git(git, repo_root, "rev-parse", "--verify", f"{history_ref}^{{commit}}").strip()
    log = run_git(
        git, repo_root, "log", "--first-parent", "--reverse", "--format=%H%x09%cI",
        revision, "--", SPDX_PATH,
    )
    commits = []
    for line in log.splitlines():
        commit, timestamp = line.split("\t", 1)
        committed_on = datetime.fromisoformat(timestamp).astimezone(timezone.utc).date()
        commits.append((commit, committed_on))
    cves, _ = build_entry_map(document)
    current = count_inventory(document, cves)
    cache: dict[str, dict[str, Any]] = {}

    def snapshot(commit: str) -> dict[str, Any]:
        if commit not in cache:
            cache[commit] = load_history_snapshot(git, repo_root, commit, SPDX_PATH)
        return cache[commit]

    eligible = [commit for commit, committed_on in commits if committed_on <= today]
    pending = not eligible or document != snapshot(eligible[-1])
    selected = update_day_snapshots(commits, today, days)
    if pending:
        # Local edits count as today's update, replacing any committed point today.
        selected = [(day, commit) for day, commit in selected if day != today]
        selected.append((today, "working-tree"))
        selected = selected[-days:]
    daily = []
    for day, commit in selected:
        counts = current if commit == "working-tree" else count_inventory(snapshot(commit), cves)
        daily.append({"date": day.isoformat(), "source": commit, **counts})
    return {
        "schema_version": 2,
        "as_of_date": today.isoformat(),
        "timezone": "UTC",
        "history_ref": history_ref,
        "cves": cves,
        "days": days,
        "day_selection": "inventory-updates",
        "current": current,
        "daily": daily,
    }


def render_chart(statistics: dict[str, Any]) -> bytes:
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        from matplotlib.ticker import MaxNLocator
    except ImportError as exc:
        raise GenerationError(
            "PNG generation requires matplotlib. In a virtual environment, run "
            "python -m pip install -r tools/requirements-statistics.txt"
        ) from exc

    daily = statistics["daily"]
    positions = list(range(len(daily)))
    peak = max(row["counts"]["tracked"] for row in daily)
    with plt.rc_context({"font.family": "DejaVu Sans", "font.size": 11}):
        fig, axis = plt.subplots(figsize=(10, 5.8))
        fig.subplots_adjust(left=0.09, right=0.98, top=0.85, bottom=0.25)
        axis.set_title("php2shell | Product status by update day", loc="left", fontsize=18, fontweight="bold", pad=24)
        bottoms = [0] * len(daily)
        for key, color in COLORS.items():
            values = [row["counts"][key] for row in daily]
            bars = axis.bar(positions, values, bottom=bottoms, width=0.55, color=color, label=LABELS[key])
            for bar, value, bottom in zip(bars, values, bottoms):
                # Tiny segments stay in the stack without overlapping number labels.
                if value and value >= peak * 0.055:
                    axis.text(bar.get_x() + bar.get_width() / 2, bottom + value / 2,
                              f"{value:,}", ha="center", va="center", color="white", fontweight="bold", fontsize=12)
            bottoms = [bottom + value for bottom, value in zip(bottoms, values)]
        for position, row in zip(positions, daily):
            total = row["counts"]["tracked"]
            axis.annotate(f"{total:,}", (position, total), xytext=(0, 6), textcoords="offset points",
                          ha="center", fontweight="bold", fontsize=13)
        axis.set_ylim(0, max(1, peak * 1.15))
        axis.set_xlim(-0.65, len(daily) - 0.35)
        axis.yaxis.set_major_locator(MaxNLocator(integer=True, nbins=8))
        axis.set_ylabel("Number of products")
        axis.set_xlabel("Inventory update date (UTC)", labelpad=8, fontsize=10)
        axis.grid(axis="y", color="#edf0f3")
        axis.set_axisbelow(True)
        axis.spines[["top", "right"]].set_visible(False)
        axis.spines[["left", "bottom"]].set_color("#475569")
        axis.set_xticks(positions, [date.fromisoformat(row["date"]).strftime("%d %b %Y") for row in daily])
        axis.legend(loc="upper center", bbox_to_anchor=(0.5, -0.23), ncol=3, frameon=False, fontsize=10)
        buffer = io.BytesIO()
        fig.savefig(buffer, format="png", dpi=160, facecolor="white", metadata={"Software": "php2shell inventory statistics"})
        plt.close(fig)
    return buffer.getvalue()


def render_readme_section(statistics: dict[str, Any]) -> str:
    current = statistics["current"]["counts"]
    lines = [
        HEADING, "", BEGIN, "",
        f"Statistics as of **{statistics['as_of_date']} (UTC)**, from the current SPDX inventory.", "",
        "| Products tracked | Fixed | Vulnerable | Under investigation | Not affected | Unassessed / unknown |",
        "| ---: | ---: | ---: | ---: | ---: | ---: |",
        "| " + " | ".join(f"{current[key]:,}" for key in LABELS) + " |", "",
        f"![Product status on the last {len(statistics['daily'])} inventory update days]({OUTPUT_DIR}/inventory-statistics.png)", "",
        f"[Counts by update day and per-CVE statistics (JSON)]({OUTPUT_DIR}/inventory-statistics.json) "
        "| [Software list](software/software_list.md)", "", END,
    ]
    return "\n".join(lines)


def update_readme(text: str, statistics: dict[str, Any]) -> str:
    text = ensure_readme_links(text)
    section = render_readme_section(statistics)
    if BEGIN in text or END in text:
        pattern = re.compile(rf"^{re.escape(HEADING)}\n\n{re.escape(BEGIN)}.*?{re.escape(END)}", re.MULTILINE | re.DOTALL)
        if text.count(BEGIN) != 1 or text.count(END) != 1 or not pattern.search(text):
            raise GenerationError("README statistics markers are incomplete or duplicated.")
        text = pattern.sub(lambda _: section, text, count=1)
    else:
        if HEADING in text:
            raise GenerationError("README statistics heading exists without generated markers.")
        marker = "## Latest software status updates"
        if marker not in text:
            raise GenerationError(f"README is missing expected heading: {marker}")
        text = text.replace(marker, section + "\n\n" + marker, 1)

    counts = statistics["current"]["counts"]
    summary = (
        f"{SUMMARY_BEGIN}\n"
        f"This repository tracks **{counts['tracked']:,} products**, including "
        f"**{counts['vulnerable']:,} vulnerable** and **{counts['fixed']:,} fixed**.\n"
        f"{SUMMARY_END}"
    )
    if SUMMARY_BEGIN in text or SUMMARY_END in text:
        pattern = re.compile(rf"{re.escape(SUMMARY_BEGIN)}.*?{re.escape(SUMMARY_END)}", re.DOTALL)
        if text.count(SUMMARY_BEGIN) != 1 or text.count(SUMMARY_END) != 1 or not pattern.search(text):
            raise GenerationError("README statistics summary markers are incomplete or duplicated.")
        return pattern.sub(lambda _: summary, text, count=1)
    marker = "## Current status\n"
    if marker not in text:
        raise GenerationError("README is missing expected heading: ## Current status")
    return text.replace(marker, marker + "\n" + summary + "\n", 1)


def positive_days(value: str) -> int:
    days = int(value)
    if days < 1:
        raise argparse.ArgumentTypeError("days must be at least 1")
    return days


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--days", type=positive_days, default=3, help="Most recent inventory update dates (default: 3).")
    parser.add_argument("--history-ref", default="HEAD", help="Mainline Git revision; use origin/main on PR branches.")
    args = parser.parse_args(argv)
    try:
        repo_root = repository_root(git_executable())
        document = load_json(repo_root / SPDX_PATH)
        statistics = build_statistics(repo_root, document, args.history_ref, args.days, datetime.now(timezone.utc).date())
        readme_path = repo_root / "README.md"
        readme = update_readme(readme_path.read_text(encoding="utf-8"), statistics)
        chart = render_chart(statistics)
        output = repo_root / OUTPUT_DIR
        output.mkdir(parents=True, exist_ok=True)
        write_generated_text(output / "inventory-statistics.json", json.dumps(statistics, indent=2) + "\n")
        png = output / "inventory-statistics.png"
        if not png.exists() or png.read_bytes() != chart:
            png.write_bytes(chart)
        write_generated_text(readme_path, readme)
    except (GenerationError, OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"Updated README statistics and {OUTPUT_DIR}: {statistics['current']['counts']['tracked']} products, {len(statistics['daily'])} update days.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
