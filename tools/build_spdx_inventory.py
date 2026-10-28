#!/usr/bin/env python3
"""Compile the inventory from every JSON fragment in shared/ and segments/."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tempfile
from pathlib import Path
from typing import Any

DEFAULT_SPDX_DIR = Path(__file__).resolve().parents[1] / "software" / "spdx"
INVENTORY_FILENAME = "PHP_Downstream_Inventory.spdx3.json"
SOURCE_DIRECTORIES = ("shared", "segments")
SCALAR_REFERENCES = ("creationInfo", "suppliedBy", "from", "security_assessedElement")
ARRAY_REFERENCES = ("to", "element", "rootElement", "createdBy", "createdUsing")


class CompilationError(ValueError):
    """Raised when fragments cannot be compiled without ambiguity or data loss."""


def unique_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CompilationError(f"Duplicate JSON key: {key}")
        result[key] = value
    return result


def load_json(path: Path) -> dict[str, Any]:
    try:
        document = json.loads(path.read_text(encoding="utf-8-sig"), object_pairs_hook=unique_keys)
    except (OSError, ValueError) as exc:
        raise CompilationError(f"Cannot load {path}: {exc}") from exc
    if not isinstance(document, dict) or not isinstance(document.get("@graph"), list):
        raise CompilationError(f"{path}: expected an object with an '@graph' array.")
    return document


def element_id(element: dict[str, Any]) -> str:
    identifier = element.get("spdxId") or element.get("@id")
    if not isinstance(identifier, str) or not identifier.strip():
        raise CompilationError("Each graph element needs a non-empty spdxId or @id.")
    return identifier


def source_files(spdx_dir: Path) -> list[Path]:
    paths: list[Path] = []
    for name in SOURCE_DIRECTORIES:
        directory = spdx_dir / name
        if not directory.is_dir():
            raise CompilationError(f"Missing source directory: {directory}")
        paths.extend(sorted(directory.rglob("*.json")))
    if not paths:
        raise CompilationError(f"No JSON fragments found under {spdx_dir}.")
    return paths


def validate_graph(document: dict[str, Any]) -> None:
    graph = document["@graph"]
    index: dict[str, dict[str, Any]] = {}
    for element in graph:
        if not isinstance(element, dict) or not isinstance(element.get("type"), str):
            raise CompilationError("Each graph element must be an object with a type.")
        identifier = element_id(element)
        if identifier in index:
            raise CompilationError(f"Duplicate graph identifier: {identifier}")
        index[identifier] = element

    assessments: dict[tuple[str, str], str] = {}
    for identifier, element in index.items():
        for field in (*SCALAR_REFERENCES, *ARRAY_REFERENCES):
            if field not in element:
                continue
            value = element[field]
            if field in ARRAY_REFERENCES:
                if not isinstance(value, list):
                    raise CompilationError(f"{identifier}: {field} must be an array.")
                references = value
            else:
                references = [value]
            for reference in references:
                if not isinstance(reference, str) or reference not in index:
                    raise CompilationError(f"{identifier}: unresolved {field} reference {reference!r}.")
            if len(references) != len(set(references)):
                raise CompilationError(f"{identifier}: duplicate references in {field}.")
        if element["type"].startswith("security_Vex"):
            if not element.get("from") or not element.get("to") or not element.get("relationshipType"):
                raise CompilationError(f"{identifier}: VEX needs from, to and relationshipType.")
            for target in element["to"]:
                key = (element["from"], target)
                status = element["relationshipType"]
                if key in assessments and assessments[key] != status:
                    raise CompilationError(f"{identifier}: conflicting VEX statuses for {key}.")
                assessments[key] = status

    documents = [node for node in graph if node["type"] == "SpdxDocument"]
    bundles = [node for node in graph if node["type"] == "Bundle"]
    if len(documents) != 1 or len(bundles) != 1:
        raise CompilationError("The inventory must contain exactly one SpdxDocument and one Bundle.")
    if documents[0].get("rootElement") != [element_id(bundles[0])]:
        raise CompilationError("The inventory document must point to the inventory bundle.")
    members = set(bundles[0].get("element", []))
    for identifier, element in index.items():
        if (element["type"] in {"software_Package", "Relationship", "security_Vulnerability"}
                or element["type"].startswith("security_Vex")) and identifier not in members:
            raise CompilationError(f"{identifier}: missing from the inventory bundle's element array.")


def compile_inventory(spdx_dir: Path) -> tuple[dict[str, Any], str, list[Path]]:
    paths = source_files(spdx_dir)
    context: Any = None
    newline: str | None = None
    elements: dict[str, dict[str, Any]] = {}
    origins: dict[str, Path] = {}
    order: dict[str, int] = {}
    positions: dict[int, str] = {}

    for path in paths:
        fragment = load_json(path)
        unknown = set(fragment) - {"@context", "@graph", "_compiler"}
        if unknown:
            raise CompilationError(f"{path}: unsupported top-level fields: {sorted(unknown)}")
        if not fragment.get("@context"):
            raise CompilationError(f"{path}: missing @context.")
        if context is None:
            context = fragment["@context"]
        elif fragment["@context"] != context:
            raise CompilationError(f"{path}: @context differs from the other fragments.")

        metadata = fragment.get("_compiler", {})
        if not isinstance(metadata, dict) or set(metadata) - {"element_order", "newline"}:
            raise CompilationError(f"{path}: invalid _compiler metadata.")
        if "newline" in metadata:
            value = metadata["newline"]
            if value not in ("\n", "\r\n") or (newline is not None and newline != value):
                raise CompilationError(f"{path}: invalid or conflicting output newline setting.")
            newline = value

        local_ids: set[str] = set()
        for element in fragment["@graph"]:
            if not isinstance(element, dict):
                raise CompilationError(f"{path}: graph elements must be objects.")
            identifier = element_id(element)
            if identifier in elements:
                raise CompilationError(f"Duplicate identifier {identifier} in {origins[identifier]} and {path}.")
            elements[identifier] = element
            origins[identifier] = path
            local_ids.add(identifier)

        local_order = metadata.get("element_order", {})
        if not isinstance(local_order, dict):
            raise CompilationError(f"{path}: element_order must be an ID-to-position object.")
        for identifier, position in local_order.items():
            if identifier not in local_ids or type(position) is not int or position < 0:
                raise CompilationError(f"{path}: invalid element_order entry for {identifier}.")
            if position in positions:
                raise CompilationError(f"{path}: order position {position} is already used by {positions[position]}.")
            order[identifier] = position
            positions[position] = identifier

    # Imported elements retain their original positions; new IDs sort after them.
    identifiers = sorted(elements, key=lambda identifier: (identifier not in order, order.get(identifier, 0), identifier))
    document = {"@context": context, "@graph": [elements[identifier] for identifier in identifiers]}
    validate_graph(document)
    return document, newline or "\n", paths


def serialize_inventory(document: dict[str, Any], newline: str) -> bytes:
    return (json.dumps(document, ensure_ascii=False, indent=2) + "\n").replace("\n", newline).encode("utf-8")


def compare_bytes(compiled: bytes, path: Path) -> None:
    reference = path.read_bytes()
    if compiled != reference:
        same_json = json.loads(compiled) == json.loads(reference)
        detail = "JSON values match, but bytes differ" if same_json else "JSON content or graph order differs"
        raise CompilationError(f"Comparison failed against {path}: {detail}.")


def write_inventory(path: Path, content: bytes) -> None:
    if path.exists() and path.read_bytes() == content:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=path.parent, prefix=path.name + ".", suffix=".tmp", delete=False) as handle:
        temporary = Path(handle.name)
        handle.write(content)
    try:
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--spdx-dir", type=Path, default=DEFAULT_SPDX_DIR)
    parser.add_argument("-o", "--output", type=Path, help="Defaults to the compiled inventory in --spdx-dir.")
    parser.add_argument("--check", action="store_true", help="Check the compiled output is current without writing it.")
    parser.add_argument("--compare", type=Path, help="Require an exact byte match with this file before writing.")
    args = parser.parse_args(argv)
    output = args.output or args.spdx_dir / INVENTORY_FILENAME
    try:
        if any(output.resolve().is_relative_to((args.spdx_dir / name).resolve()) for name in SOURCE_DIRECTORIES):
            raise CompilationError("Output must be outside shared/ and segments/.")
        document, newline, paths = compile_inventory(args.spdx_dir)
        content = serialize_inventory(document, newline)
        if args.compare:
            compare_bytes(content, args.compare)
        if args.check:
            compare_bytes(content, output)
        else:
            write_inventory(output, content)
    except (CompilationError, OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    verb = "Verified" if args.check else "Compiled"
    print(f"{verb} {len(document['@graph'])} elements from {len(paths)} JSON files: {output}")
    if args.compare:
        print(f"Byte-for-byte match with {args.compare}.")
    print(f"SHA-256: {hashlib.sha256(content).hexdigest()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
