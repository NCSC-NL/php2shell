#!/usr/bin/env python3
"""Generate README statistics and a daily PNG chart from SPDX and Git history."""

from __future__ import annotations

import argparse
import io
import json
import re
import sys
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from generate_software_list_from_spdx3 import (
    GenerationError,
    build_entry_map,
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
    "tracked": "#2563eb",
    "fixed": "#15803d",
    "vulnerable": "#dc2626",
    "investigation": "#b77909",
    "not_affected": "#7c3aed",
    "unknown": "#64748b",
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


def daily_snapshots(
    commits: list[tuple[str, date]], end_date: date, days: int
) -> list[tuple[date, str | None]]:
    """Select the last mainline snapshot available at each UTC day end.

    Commits are in mainline order, not timestamp order: merged branches and
    clock skew must not cause an older tree to replace a newer mainline tree.
    No snapshot before the first observation means missing data, never zero.
    """
    start = end_date - timedelta(days=days - 1)
    snapshots = []
    for offset in range(days):
        day = start + timedelta(days=offset)
        eligible = [commit for commit, committed_on in commits if committed_on <= day]
        snapshots.append((day, eligible[-1] if eligible else None))
    return snapshots


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
    daily = []
    for day, commit in daily_snapshots(commits, today, days):
        if day == today:
            daily.append({"date": day.isoformat(), "source": "working-tree", **current})
        elif commit:
            if commit not in cache:
                snapshot = load_history_snapshot(git, repo_root, commit, SPDX_PATH)
                cache[commit] = count_inventory(snapshot, cves)
            daily.append({"date": day.isoformat(), "source": commit, **cache[commit]})
        else:
            daily.append({"date": day.isoformat(), "source": None, "counts": None, "by_cve": None})
    return {
        "schema_version": 1,
        "as_of_date": today.isoformat(),
        "timezone": "UTC",
        "history_ref": history_ref,
        "cves": cves,
        "days": days,
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
    current = daily[-1]["counts"]
    positions = list(range(len(daily)))
    with plt.rc_context({"font.family": "DejaVu Sans", "font.size": 11}):
        fig, axes = plt.subplots(
            2, 1, figsize=(12, 7.2), sharex=True,
            gridspec_kw={"height_ratios": [1, 2]}, layout="constrained",
        )
        fig.suptitle("PHP downstream inventory | daily status", fontsize=19, fontweight="bold")
        axes[0].set_title(
            f"{daily[0]['date']} to {daily[-1]['date']} (UTC) | {current['tracked']:,} products tracked",
            loc="left", fontsize=11, color="#475569", pad=12,
        )
        for key, label in LABELS.items():
            axis = axes[0] if key == "tracked" else axes[1]
            values = [row["counts"][key] if row["counts"] is not None else float("nan") for row in daily]
            axis.plot(
                positions, values, color=COLORS[key], linewidth=2.4, marker="o",
                markersize=4, linestyle="--" if key == "unknown" else "-",
                label=f"{label} ({current[key]:,})",
            )
        for axis in axes:
            peak = max(
                (value for line in axis.lines for value in line.get_ydata() if value == value),
                default=0,
            )
            axis.set_ylim(0, max(1, peak * 1.12))
            axis.yaxis.set_major_locator(MaxNLocator(integer=True, nbins=5))
            axis.set_ylabel("Products")
            axis.grid(axis="y", color="#e2e8f0")
            axis.set_axisbelow(True)
            axis.spines[["top", "right"]].set_visible(False)
            axis.spines[["left", "bottom"]].set_color("#cbd5e1")
            axis.legend(loc="upper left", bbox_to_anchor=(1.01, 1), frameon=False, fontsize=10)
        step = max(1, (len(daily) + 9) // 10)
        ticks = sorted(set([*positions[::step], positions[-1]]))
        axes[1].set_xticks(ticks, [date.fromisoformat(daily[i]["date"]).strftime("%d %b") for i in ticks])
        axes[1].set_xlabel("End-of-day Git snapshots; latest day uses the current inventory. Gaps mean no history.", labelpad=12, fontsize=9)
        buffer = io.BytesIO()
        fig.savefig(buffer, format="png", dpi=160, facecolor="white", metadata={"Software": "php2shell inventory statistics"})
        plt.close(fig)
    return buffer.getvalue()


def render_readme_section(statistics: dict[str, Any]) -> str:
    current = statistics["daily"][-1]["counts"]
    lines = [
        HEADING, "", BEGIN, "",
        f"Statistics as of **{statistics['as_of_date']} (UTC)**, from the current SPDX inventory.", "",
        "| Products tracked | Fixed | Vulnerable | Under investigation | Not affected | Unassessed / unknown |",
        "| ---: | ---: | ---: | ---: | ---: | ---: |",
        "| " + " | ".join(f"{current[key]:,}" for key in LABELS) + " |", "",
        f"![Daily product counts and vulnerability status over the last {statistics['days']} days]({OUTPUT_DIR}/inventory-statistics.png)", "",
        "Each product/component entry is counted once across " + ", ".join(statistics["cves"]) + ". "
        "Vulnerable takes priority, followed by under investigation, then missing/unknown assessments. "
        "Fixed means every tracked CVE is fixed or not affected, with at least one fix; "
        "not affected means all tracked CVEs are not affected. "
        "A fix refers to the listed version scope, not every deployed version.", "",
        "The chart uses the last mainline SPDX snapshot per UTC day and carries counts forward on days without changes. "
        "The latest day includes local inventory changes; dates before available history have no counts.", "",
        f"[Daily counts and per-CVE statistics (JSON)]({OUTPUT_DIR}/inventory-statistics.json) "
        "| [Software list](software/software_list.md)", "", END,
    ]
    return "\n".join(lines)


def update_readme(text: str, statistics: dict[str, Any]) -> str:
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

    counts = statistics["daily"][-1]["counts"]
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
    parser.add_argument("--days", type=positive_days, default=7, help="Calendar days including today (default: 7).")
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
    print(f"Updated README statistics and {OUTPUT_DIR}: {statistics['daily'][-1]['counts']['tracked']} products, {args.days} days.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
