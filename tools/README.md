# Tools

This repository tracks CVE-2026-109618 and CVE-2026-109619. PHP's official advisory identifies PHP 8.5.12, 8.4.27, 8.3.36 and 8.2.35 as fixed upstream releases.

## `build_spdx_inventory.py`

Compiles every `.json` file recursively under `software/spdx/shared/` and
`software/spdx/segments/` into `software/spdx/PHP_Downstream_Inventory.spdx3.json`.
File discovery is automatic; there is no manifest. Neither the existing compiled
file is read as input to compilation.

```bash
python tools/build_spdx_inventory.py
python tools/build_spdx_inventory.py --check
```

The compiler rejects duplicate IDs, unresolved references, conflicting VEX statuses,
incompatible contexts, and missing bundle members. `--check` fails if the compiled
file is stale and does not write anything. `--spdx-dir` selects another source root;
`--output` selects another output file outside the source directories.

Use `--check` alone for routine verification. See [source maintenance](../software/spdx/README.md)
for fragment ownership and ordering rules.

## `split_spdx_inventory.py`

The one-time migration utility partitions the legacy graph by product category,
retains shared assessments intact, and records ordering metadata so compilation
can reproduce the original bytes. It refuses to overwrite existing source JSON.

```bash
python tools/split_spdx_inventory.py original.spdx3.json --spdx-dir new-spdx-directory
```

## `generate_software_list_from_spdx3.py`

Generates the alphabetized Markdown software list in `software/` from the compiled SPDX 3 JSON document.

Usage:

```bash
python tools/build_spdx_inventory.py
python tools/generate_software_list_from_spdx3.py PHP_Downstream_Inventory.spdx3.json -o software
```

By default, the tool updates only the alphabetized `software_list*.md` pages. To also regenerate the full status history and refresh the root README latest-updates table, pass both opt-in flags:

```bash
python tools/build_spdx_inventory.py
python tools/generate_software_list_from_spdx3.py PHP_Downstream_Inventory.spdx3.json -o software --update-history --update-readme
python tools/generate_inventory_statistics.py
```

The generated history file is `software/changelog_software_list.md`. It uses the same columns as the alphabetized lists, with a leading `Date and time` column in `YYYY-MM-DD HH:MM:SS +/-HHMM` format. The README contains the five most recent status updates in a compact table that merges per-CVE statuses into one column and omits notes, then links to the full history.

Both README generators preserve the existing contents table and ensure it includes
the [Community contributions](https://github.com/NCSC-NL/php2shell/blob/community-contributions/COMMUNITY_CONTRIBUTIONS.MD)
link. The permanent row is defined by `README_COMMUNITY_ROW` in
`generate_software_list_from_spdx3.py` and restored if missing. Restoring or correcting
this row updates the operational timestamp without changing the software-status date.

History defaults to `HEAD`. On a pull request branch, fetch the latest `main`, merge it before editing SPDX, and add `--history-ref origin/main` to the command above. This preserves the mainline update timestamps instead of treating merges into the PR branch as new status updates. Status changes not yet present on the selected history reference are included as pending updates.

When only a filename is provided, the tool reads it from `software/spdx/`. An explicit path may also be provided.

## `generate_inventory_statistics.py`

Updates the generated statistics section in the root `README.md` and writes
`software/statistics/inventory-statistics.png` and `inventory-statistics.json`.
It also refreshes the one-sentence tracked/vulnerable/fixed summary directly under
`## Current status`.
The default chart shows stacked bars for the three most recent UTC dates with
inventory updates, with totals above the bars and counts inside larger segments.
The JSON includes current totals, counts by update date, and separate counts for
each tracked CVE.

Use Python 3.10 or newer, Git with full history, and Matplotlib. Install the plotting
dependency in a virtual environment (the other generators still use only the
standard library):

```bash
python -m venv .venv
# Bash: source .venv/bin/activate
# PowerShell: .\.venv\Scripts\Activate.ps1
python -m pip install -r tools/requirements-statistics.txt
python tools/generate_inventory_statistics.py
```

Run statistics after compiling SPDX and generating the Markdown on every inventory
update, and on periodic refreshes even if no statuses changed. The script itself
does not schedule jobs or commit files. A scheduled runner must check out full Git
history (for GitHub Actions, use `fetch-depth: 0`) and run the same commands.
Shallow clones fail explicitly rather than silently publishing incomplete trends.

```bash
python tools/build_spdx_inventory.py
python -m json.tool software/spdx/PHP_Downstream_Inventory.spdx3.json
python tools/generate_software_list_from_spdx3.py PHP_Downstream_Inventory.spdx3.json -o software --update-history --update-readme
python tools/generate_inventory_statistics.py --days 3
```

On a PR branch, add `--history-ref origin/main` to **both** generators after
fetching and merging the latest mainline. Statistics use the last compiled SPDX
snapshot in first-parent history per UTC day, dated by the commit's committer time
(so merged updates appear when they reach mainline). `--days N` selects the last N
distinct dates that changed the compiled inventory, skipping days without updates
even when the selected dates are more than N calendar days apart. Multiple updates
on one day produce one bar using that day's last snapshot. If fewer dates exist,
only the available dates are shown.

Local inventory changes compared with the latest mainline snapshot count as an
update today, replacing today's committed bar or adding a new one. A periodic run
without inventory changes does not add a bar. The README totals and summary always
use the current local inventory. All historical dates are assessed against the
current inventory's CVE set; missing assessments count as unknown. JSON schema
version 2 stores current totals in `current` and the selected update dates in
`daily`; `days` is the requested number of update dates, not a calendar window.

Each unique SPDX package ID counts as one product/component entry, matching the
software list. Overall categories are mutually exclusive: any `Vulnerable` status
takes priority, then any `Investigation`, then missing or unrecognized assessments.
A product is `Fixed` only if all tracked CVEs are `Fix` or `Not vuln` and at least
one is `Fix`. It is `Not affected` only if all are `Not vuln`. The status counts
therefore sum to the tracked total, without counting a product twice for two CVEs.
Fixed counts describe the listed version scope, not all deployments.

The statistics section has its own UTC snapshot date. Refreshing it preserves the
operational and latest-status timestamps and other README sections. Repeating the
command on the same UTC day with the same inputs leaves output bytes unchanged.
Do not edit the generated summary, section, PNG, or JSON by hand.
