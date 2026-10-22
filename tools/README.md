# Tools

This repository tracks CVE-2026-109618 and CVE-2026-109619. PHP's official advisory identifies PHP 8.5.12, 8.4.27, 8.3.36 and 8.2.35 as fixed upstream releases.

## `generate_software_list_from_spdx3.py`

Generates the alphabetized Markdown software list in `software/` from an SPDX 3 JSON document.

Usage:

```bash
python tools/generate_software_list_from_spdx3.py PHP_Downstream_Inventory.spdx3.json -o software
```

By default, the tool updates only the alphabetized `software_list*.md` pages. To also regenerate the full status history and refresh the root README latest-updates table, pass both opt-in flags:

```bash
python tools/generate_software_list_from_spdx3.py PHP_Downstream_Inventory.spdx3.json -o software --update-history --update-readme
```

The generated history file is `software/changelog_software_list.md`. It uses the same columns as the alphabetized lists, with a leading `Date and time` column in `YYYY-MM-DD HH:MM:SS +/-HHMM` format. The README contains the five most recent status updates in a compact table that merges per-CVE statuses into one column and omits notes, then links to the full history.

History defaults to `HEAD`. On a pull request branch, fetch the latest `main`, merge it before editing SPDX, and add `--history-ref origin/main` to the command above. This preserves the mainline update timestamps instead of treating merges into the PR branch as new status updates. Status changes not yet present on the selected history reference are included as pending updates.

When only a filename is provided, the tool reads it from `software/spdx/`. An explicit path may also be provided.
