#!/usr/bin/env python3
"""Read-only PE triage used to select representative samples for IDA."""

from __future__ import annotations

import argparse
import concurrent.futures
import csv
import math
import os
from collections import Counter
from pathlib import Path

import pefile


PACKER_SECTION_TERMS = (
    "upx", "aspack", "mpress", "petite", "pec", "themida", "vmp",
    "packed", "compress", "nsp", "y0da", "enigma",
)


def entropy(section) -> float:
    try:
        return round(float(section.get_entropy()), 4)
    except Exception:
        return 0.0


def section_name(section) -> str:
    return section.Name.rstrip(b"\0").decode("ascii", "replace")


def has_data_directory(entries, index: int) -> bool:
    """Return False for valid-but-truncated optional-header directory tables."""
    if index >= len(entries):
        return False
    entry = entries[index]
    return bool(entry.VirtualAddress and entry.Size)


def analyze(row: dict[str, str], root: Path) -> dict[str, object]:
    path = root / row["batch_id"] / f"{row['dataset_sha256']}.exe"
    result: dict[str, object] = {
        "dataset_sha256": row["dataset_sha256"],
        "family": row["family"],
        "batch_id": row["batch_id"],
        "size_bytes": int(row["size_bytes"]),
        "pe_kind": row["pe_kind"],
        "path": str(path),
        "status": "ok",
        "error": "",
    }
    try:
        pe = pefile.PE(str(path), fast_load=True)
        directories = [
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT"],
        ]
        pe.parse_data_directories(directories=directories)

        imports = []
        modules = []
        for attribute in ("DIRECTORY_ENTRY_IMPORT", "DIRECTORY_ENTRY_DELAY_IMPORT"):
            for module in getattr(pe, attribute, ()):
                module_name = (module.dll or b"").decode("ascii", "replace")
                modules.append(module_name)
                for item in module.imports:
                    name = (
                        item.name.decode("ascii", "replace")
                        if item.name
                        else f"ordinal_{item.ordinal}"
                    )
                    imports.append(name)

        sections = []
        executable_entropies = []
        writable_executable = 0
        for section in pe.sections:
            name = section_name(section)
            value = entropy(section)
            is_executable = bool(section.Characteristics & 0x20000000)
            is_writable = bool(section.Characteristics & 0x80000000)
            sections.append((name, value, int(section.SizeOfRawData), is_executable, is_writable))
            if is_executable:
                executable_entropies.append(value)
            if is_executable and is_writable:
                writable_executable += 1

        entry_rva = int(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
        entry_section = pe.get_section_by_rva(entry_rva)
        entry_name = section_name(entry_section) if entry_section else ""
        entry_entropy = entropy(entry_section) if entry_section else 0.0
        max_exec_entropy = max(executable_entropies, default=0.0)
        named_packer_section = any(
            term in name.lower() for name, *_ in sections for term in PACKER_SECTION_TERMS
        )
        low_imports_high_entropy = len(imports) <= 8 and max_exec_entropy >= 7.1
        suspicious_entry = bool(
            entry_section
            and (
                int(entry_section.SizeOfRawData) == 0
                or (
                    entry_section.Characteristics & 0xA0000000 == 0xA0000000
                    and entry_entropy >= 6.8
                )
            )
        )
        likely_packed = named_packer_section or low_imports_high_entropy or suspicious_entry

        directory = pe.OPTIONAL_HEADER.DATA_DIRECTORY
        dotnet = has_data_directory(directory, 14)
        signed = has_data_directory(directory, 4)
        tls = has_data_directory(directory, 9)
        overlay_offset = pe.get_overlay_data_start_offset()
        overlay_bytes = max(0, path.stat().st_size - overlay_offset) if overlay_offset else 0

        result.update(
            {
                "section_count": len(sections),
                "section_names": "|".join(name for name, *_ in sections),
                "import_module_count": len(set(modules)),
                "import_count": len(imports),
                "import_modules": "|".join(sorted(set(modules), key=str.lower)),
                "max_exec_entropy": max_exec_entropy,
                "entry_section": entry_name,
                "entry_entropy": entry_entropy,
                "writable_executable_sections": writable_executable,
                "named_packer_section": named_packer_section,
                "low_imports_high_entropy": low_imports_high_entropy,
                "suspicious_entry": suspicious_entry,
                "likely_packed": likely_packed,
                "dotnet": dotnet,
                "signed": signed,
                "tls": tls,
                "overlay_bytes": overlay_bytes,
                "overlay_ratio": round(overlay_bytes / max(path.stat().st_size, 1), 6),
            }
        )
        pe.close()
    except Exception as exc:
        result["status"] = "error"
        result["error"] = f"{type(exc).__name__}: {exc}"
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--limit", type=int)
    args = parser.parse_args()

    root = args.root.resolve()
    manifest = (args.manifest or root / "repair_manifest.csv").resolve()
    with manifest.open("r", encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.DictReader(handle))
    if args.limit:
        rows = rows[: args.limit]

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = [executor.submit(analyze, row, root) for row in rows]
        for index, future in enumerate(concurrent.futures.as_completed(futures), 1):
            results.append(future.result())
            if index % 250 == 0 or index == len(futures):
                print(f"progress: {index}/{len(futures)}", flush=True)

    results.sort(key=lambda row: (int(str(row["batch_id"]).split("_")[1]), row["dataset_sha256"]))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    part = args.output.with_name(args.output.name + ".part")
    fieldnames = list(results[0])
    with part.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)
    os.replace(part, args.output)

    status = Counter(str(row["status"]) for row in results)
    packed = sum(str(row.get("likely_packed", "")).lower() == "true" for row in results)
    print(f"status={dict(status)} likely_packed={packed}/{len(results)} output={args.output}")
    return 1 if status.get("error") else 0


if __name__ == "__main__":
    raise SystemExit(main())
