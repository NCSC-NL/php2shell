# SPDX inventory sources

Edit JSON fragments in `segments/` and `shared/`, then compile them:

```bash
python tools/build_spdx_inventory.py
python tools/generate_software_list_from_spdx3.py PHP_Downstream_Inventory.spdx3.json -o software --update-history --update-readme
```

Run these commands from the repository root. Every `.json` file in those two
directories, including nested directories, is discovered automatically. Adding a
source file requires no registration or manifest. Keep non-source JSON files outside these
directories because every JSON file inside them is an input.

`PHP_Downstream_Inventory.spdx3.json` is the generated full inventory. Keep it in
version control alongside source edits so the existing Markdown and Git status
history generators can continue reading the same file. Its path and package IDs
remain stable. The compiler can recreate it even when the output file is absent.

## Categories

| Segment | Scope |
| --- | --- |
| `runtime-core.json` | PHP core, SAPIs, bundled modules, external extensions, embedded and alternative runtimes |
| `os-distributions.json` | Linux and BSD PHP packages, Windows binaries, Homebrew, vendor extended-support packages |
| `containers-images.json` | Docker/OCI images, CI runtime images, buildpacks |
| `edge-devices.json` | Firewalls, NAS, routers, ADCs, appliance firmware and bundled device packages |
| `hosting-cloud.json` | Hosting panels, managed platforms, hosted services, serverless runtime layers |
| `applications.json` | CMS, commerce, collaboration, education, business, mail and analytics applications |
| `frameworks-libraries.json` | Frameworks, reusable packages, SDKs and client libraries |
| `developer-tooling.json` | Build/test tools, local development stacks and development integrations |
| `observability-admin.json` | Monitoring, administration, security operations and management consoles |
| `unclassified.json` | Entries awaiting category assignment; initially empty |

Each package has one source location. Classify the actual entry's scope: an
application's Docker image belongs in `containers-images.json`, while its generic
application entry belongs in `applications.json`. A vendor's managed service and
hardware appliance can belong in different segments. Legacy `Category:` comments
are retained as historical data; the source file now determines the segment.

## Shared elements

| File | Contents |
| --- | --- |
| `shared/core.json` | Document, inventory bundle, creation information and tool |
| `shared/organizations.json` | Supplier and creator organizations |
| `shared/vulnerabilities.json` | CVE definitions |
| `shared/assessments.json` | Existing VEX assessments whose targets span multiple segments |

Package relationships live with their `from` package. Assessments targeting one
segment live in that segment; assessments spanning segments are stored once in
`shared/assessments.json`. Preserve their IDs and target arrays. Cross-file
references are validated against the complete graph during compilation.

## Fragment format

Each fragment has the original `@context` and an `@graph` array of unchanged SPDX
elements. These are source fragments, not independently complete SPDX documents:
they can refer to elements in other files and contain optional `_compiler`
metadata that is excluded from the compiled output.

`_compiler.element_order` maps existing element IDs to their original graph
positions. This preserves the exact original array order even after splitting or
moving elements between files. When moving an existing element, move its order
entry with it. When removing an element, remove its order entry and all references.
New elements can omit order entries; the compiler appends them sorted by ID.

`shared/core.json` records `_compiler.newline` to retain the original CRLF line
endings. Compilation emits UTF-8 JSON with two-space indentation and a final
newline. Git attributes preserve those line endings for the aggregate
across checkouts. Source files themselves may use LF or CRLF.

When adding packages, relationships, vulnerabilities or VEX assessments, also add
their IDs to the inventory Bundle's `element` array in `shared/core.json`. The
compiler rejects missing bundle members, duplicate identifiers (even identical
definitions), broken references and conflicting VEX statuses before replacing the
compiled file. Keep each shared element in exactly one source file.

## Verification

```bash
python tools/build_spdx_inventory.py --check
python -m unittest discover -s tests
```
