#!/usr/bin/env python3
"""One-time, lossless migration of the legacy inventory into category fragments."""

from __future__ import annotations

import argparse
from collections import defaultdict
import json
from pathlib import Path
import re
import sys
from typing import Any

if __package__:
    from . import build_spdx_inventory as compiler
else:
    import build_spdx_inventory as compiler

CATEGORY_SEGMENTS = {
    "PHP core": "runtime-core",
    "PHP bundled modules": "runtime-core",
    "PHP external extensions": "runtime-core",
    "Runtime interfaces": "runtime-core",
    "Embedded runtimes": "runtime-core",
    "Appliances and embedded": "edge-devices",
    "Hosting and cloud": "hosting-cloud",
    "Frameworks and packages": "frameworks-libraries",
    "SDKs and integrations": "frameworks-libraries",
    "Development and build": "developer-tooling",
    "Monitoring and administration": "observability-admin",
    "Business applications": "applications",
    "Education and knowledge": "applications",
    "Collaboration and storage": "applications",
    "CMS and publishing": "applications",
    "Content management": "applications",
    "Commerce": "applications",
    "Mail and analytics": "applications",
}
SEGMENTS = sorted({*CATEGORY_SEGMENTS.values(), "os-distributions", "containers-images", "unclassified"})
PACKAGE_OVERRIDES = {
    "PHP-0258": "applications",  # SolidInvoice's bundled application distribution.
    "PHP-0377": "applications",  # Nextcloud Snap distribution.
    "PHP-0378": "edge-devices",  # NextcloudPi turnkey stack.
    "PHP-0621": "hosting-cloud",  # Plesk entries lack legacy Category comments.
    "PHP-0622": "hosting-cloud",
    "PHP-0625": "observability-admin",  # Panorama management console.
    "PHP-0630": "applications",  # iBabs portal lacks a legacy Category comment.
    "PHP-0642": "hosting-cloud",  # Bref Lambda runtime layers.
    "PHP-0673": "edge-devices",  # KACE Systems Management Appliance.
    "PHP-0725": "observability-admin",  # FortiADC Manager, separate from FortiADC.
}


def package_segment(package: dict[str, Any]) -> str:
    record_id = compiler.element_id(package).rsplit(":", 1)[-1]
    if record_id in PACKAGE_OVERRIDES:
        return PACKAGE_OVERRIDES[record_id]
    category_match = re.search(r"^Category: (.+)$", package.get("comment", ""), re.MULTILINE)
    category = category_match[1].strip() if category_match else ""
    if category != "Containers and distribution":
        return CATEGORY_SEGMENTS.get(category, "unclassified")

    name = package.get("name", "")
    if name.startswith(("Synology ", "QNAP ")):
        return "edge-devices"
    if name.startswith(("XAMPP", "WampServer", "MAMP", "Laragon", "EasyPHP", "Laravel Herd", "Moodle4Mac", "Moodle Windows")):
        return "developer-tooling"
    if re.search(r"docker|container|\bimages?\b|buildpack", name, re.IGNORECASE):
        return "containers-images"
    if name.startswith(("Debian ", "Ubuntu ", "Alpine ", "Fedora ", "Arch Linux ", "FreeBSD ",
                        "Homebrew ", "Red Hat ", "SUSE Linux ", "Official PHP Windows ", "CloudLinux ",
                        "TuxCare ", "Gentoo ", "Nixpkgs ", "OpenBSD ", "OpenWrt ")):
        return "os-distributions"
    return "unclassified"


def split_document(document: dict[str, Any], newline: str) -> dict[str, dict[str, Any]]:
    compiler.validate_graph(document)
    packages = {
        compiler.element_id(node): package_segment(node)
        for node in document["@graph"] if node["type"] == "software_Package"
    }
    grouped: defaultdict[str, list[tuple[int, dict[str, Any]]]] = defaultdict(list)
    for segment in SEGMENTS:
        grouped[f"segments/{segment}.json"] = []

    for position, node in enumerate(document["@graph"]):
        kind = node["type"]
        if kind == "software_Package":
            path = f"segments/{packages[compiler.element_id(node)]}.json"
        elif kind == "Organization":
            path = "shared/organizations.json"
        elif kind == "security_Vulnerability":
            path = "shared/vulnerabilities.json"
        elif kind.startswith("security_Vex"):
            targets = {packages.get(target) for target in node.get("to", [])}
            if len(targets) == 1 and None not in targets:
                path = f"segments/{next(iter(targets))}.json"
            else:
                path = "shared/assessments.json"
        elif kind == "Relationship":
            segment = packages.get(node.get("from"))
            path = f"segments/{segment}.json" if segment else "shared/relationships.json"
        else:
            path = "shared/core.json"
        grouped[path].append((position, node))

    fragments = {}
    for path, nodes in sorted(grouped.items()):
        metadata: dict[str, Any] = {"element_order": {compiler.element_id(node): position for position, node in nodes}}
        if path == "shared/core.json":
            metadata["newline"] = newline
        fragments[path] = {
            "@context": document["@context"],
            "_compiler": metadata,
            "@graph": [node for _, node in nodes],
        }
    return fragments


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="The original inventory to split.")
    parser.add_argument("--spdx-dir", type=Path, default=compiler.DEFAULT_SPDX_DIR)
    args = parser.parse_args(argv)
    try:
        for name in compiler.SOURCE_DIRECTORIES:
            if any((args.spdx_dir / name).rglob("*.json")):
                raise compiler.CompilationError(f"{args.spdx_dir / name} already contains JSON; refusing to overwrite sources.")
        original = args.input.read_bytes()
        document = compiler.load_json(args.input)
        newline = "\r\n" if b"\r\n" in original else "\n"
        if compiler.serialize_inventory(document, newline) != original:
            raise compiler.CompilationError("Input formatting cannot be reproduced exactly by the compiler.")
        fragments = split_document(document, newline)
        for relative_path, fragment in fragments.items():
            path = args.spdx_dir / relative_path
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("x", encoding="utf-8", newline="\n") as handle:
                json.dump(fragment, handle, ensure_ascii=True, indent=2)
                handle.write("\n")
        compiled, output_newline, _ = compiler.compile_inventory(args.spdx_dir)
        compiler.compare_bytes(compiler.serialize_inventory(compiled, output_newline), args.input)
    except (compiler.CompilationError, OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    for path, fragment in fragments.items():
        nodes = fragment["@graph"]
        packages = sum(node["type"] == "software_Package" for node in nodes)
        print(f"{path}: {len(nodes)} elements, {packages} packages")
    print(f"Split {len(document['@graph'])} elements into {len(fragments)} fragments; exact reconstruction verified.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
