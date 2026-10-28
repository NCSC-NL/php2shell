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
```

The generated history file is `software/changelog_software_list.md`. It uses the same columns as the alphabetized lists, with a leading `Date and time` column in `YYYY-MM-DD HH:MM:SS +/-HHMM` format. The README contains the five most recent status updates in a compact table that merges per-CVE statuses into one column and omits notes, then links to the full history.

History defaults to `HEAD`. On a pull request branch, fetch the latest `main`, merge it before editing SPDX, and add `--history-ref origin/main` to the command above. This preserves the mainline update timestamps instead of treating merges into the PR branch as new status updates. Status changes not yet present on the selected history reference are included as pending updates.

When only a filename is provided, the tool reads it from `software/spdx/`. An explicit path may also be provided.
