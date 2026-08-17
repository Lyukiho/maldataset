#!/usr/bin/env python3
"""Extract comprehensive PE static features, failures, summaries, and plots.

Extracts 60 continuous, 30 binary, and 4 categorical features from each PE.
Splits samples per-label at --train-ratio (default 0.7) for training-set analysis.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import math
import textwrap
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import pefile

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DIRECTORY_NAMES: dict[int, str] = {
    0: "export", 1: "import", 2: "resource", 3: "exception",
    4: "security", 5: "basereloc", 6: "debug", 7: "architecture",
    8: "globalptr", 9: "tls", 10: "load_config", 11: "bound_import",
    12: "iat", 13: "delay_import", 14: "com_descriptor", 15: "reserved",
}

COMMON_SECTION_NAMES: set[str] = {
    ".text", ".code", "code", ".data", "data", ".rdata", ".bss", "bss",
    ".idata", ".edata", ".pdata", ".xdata", ".rsrc", ".reloc", ".tls",
    ".crt", ".debug", ".didat", ".gfids", ".00cfg",
}

CONTINUOUS_FEATURES: list[str] = [
    "file_size", "file_entropy", "dos_e_lfanew",
    "coff_number_of_sections", "coff_timestamp_year",
    "coff_number_of_symbols", "coff_size_of_optional_header",
    "linker_major_version", "linker_minor_version",
    "os_major_version", "os_minor_version",
    "image_major_version", "image_minor_version",
    "subsystem_major_version", "subsystem_minor_version",
    "size_of_code", "size_of_initialized_data", "size_of_uninitialized_data",
    "entry_point_rva", "entry_point_relative",
    "image_base", "section_alignment", "file_alignment",
    "size_of_image", "size_of_headers",
    "headers_to_image_ratio", "code_to_image_ratio",
    "initialized_data_to_image_ratio",
    "checksum", "number_of_rva_and_sizes",
    "stack_reserve", "stack_commit", "heap_reserve", "heap_commit",
    "section_total_raw_size", "section_total_virtual_size",
    "section_max_raw_size", "section_max_virtual_size",
    "executable_section_count", "writable_section_count", "rwx_section_count",
    "zero_raw_section_count", "nonstandard_section_name_count",
    "empty_section_name_count",
    "entry_section_index", "entry_section_raw_size", "entry_section_virtual_size",
    "section_entropy_mean", "section_entropy_max", "entry_section_entropy",
    "high_entropy_section_count",
    "overlay_size",
    "import_dll_count", "import_symbol_count", "ordinal_import_count",
    "export_symbol_count", "resource_leaf_count", "debug_entry_count",
] + [f"directory_{name}_size" for name in DIRECTORY_NAMES.values()]

BINARY_FEATURES: list[str] = [
    "packing_detected", "is_pe32_plus", "is_dll", "is_executable_image",
    "relocations_stripped", "large_address_aware",
    "timestamp_zero", "timestamp_implausible",
    "symbol_table_present", "checksum_zero",
    "dynamic_base_aslr", "nx_compatible", "control_flow_guard",
    "high_entropy_va", "force_integrity", "terminal_server_aware",
    "entry_point_in_section", "entry_section_executable",
    "entry_section_writable", "entry_section_rwx",
    "has_rwx_section", "has_nonstandard_section_name",
    "has_empty_section_name", "has_high_entropy_section",
    "has_overlay", "has_imports", "has_exports", "has_resources",
    "has_ordinal_import", "pe_structure_parse_ok",
] + [f"directory_{name}_present" for name in DIRECTORY_NAMES.values()]

CATEGORICAL_FEATURES: list[str] = [
    "machine", "optional_magic", "subsystem", "entry_section_name",
]

ALL_FEATURES: list[str] = CONTINUOUS_FEATURES + BINARY_FEATURES + CATEGORICAL_FEATURES

# Key features for the continuous distribution box-plot grid
PLOT_CONTINUOUS: list[str] = [
    "file_size", "file_entropy", "size_of_code", "size_of_image",
    "section_entropy_mean", "section_entropy_max", "entry_section_entropy",
    "import_symbol_count", "export_symbol_count", "overlay_size",
    "high_entropy_section_count", "section_total_raw_size",
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    total = len(data)
    return -sum(
        (count / total) * math.log2(count / total)
        for count in Counter(data).values()
    )


def timestamp_to_year(ts: int) -> int | None:
    """Convert a PE timestamp to a UTC year. Returns None if clearly invalid."""
    if ts <= 0:
        return None
    try:
        return datetime.fromtimestamp(ts, tz=timezone.utc).year
    except (OSError, OverflowError, ValueError):
        return None


def is_plausible_timestamp(ts: int) -> bool:
    """Timestamp is plausibly from 1990–2030."""
    year = timestamp_to_year(ts)
    return year is not None and 1990 <= year <= 2030


def clean_section_name(raw: bytes) -> str:
    try:
        return raw.decode("utf-8", errors="ignore").rstrip("\x00").strip()
    except Exception:
        return ""


def is_common_section_name(name: str) -> bool:
    return name.lower() in {n.lower() for n in COMMON_SECTION_NAMES}


def detect_packing(data: bytes, sec_names: list[str], section_entropies: list[float],
                    entry_exec: bool, entry_rva: int) -> bool:
    """Heuristic packing detection: UPX markers, high-entropy sections, suspicious entry."""
    # UPX marker
    if b"UPX!" in data[:4096]:
        return True
    if any("UPX" in n.upper() for n in sec_names):
        return True
    # High entropy (>7.5) in a writable+executable section is suspicious
    if any(e > 7.5 for e in section_entropies):
        return True
    return False


def resource_leaf_count(resource_dir: Any) -> int:
    """Count leaf data entries in a resource directory tree."""
    count = 0
    for entry in getattr(resource_dir, "entries", []):
        if hasattr(entry, "directory"):
            count += resource_leaf_count(entry.directory)
        elif hasattr(entry, "data"):
            count += 1
    return count


# ---------------------------------------------------------------------------
# Feature extraction
# ---------------------------------------------------------------------------

def _safe_int(obj: Any, attr: str, default: int = 0) -> int:
    try:
        return int(getattr(obj, attr, default) or 0)
    except Exception:
        return default


def _safe_flag(mask: int, value: int) -> int:
    return 1 if (value & mask) == mask else 0


def extract_features(data: bytes) -> dict[str, Any]:
    """Parse a PE file and return all continuous, binary, and categorical features."""
    result: dict[str, Any] = {}
    pe_structure_parse_ok = 1

    # --- parse PE --------------------------------------------------------
    try:
        pe = pefile.PE(data=data, fast_load=True)
    except Exception:
        # Not a valid PE at all — return defaults with parse_ok=0
        result["pe_structure_parse_ok"] = 0
        for f in CONTINUOUS_FEATURES:
            result[f] = 0.0 if f != "coff_timestamp_year" else 0
        for f in BINARY_FEATURES:
            result[f] = 0
        for f in CATEGORICAL_FEATURES:
            result[f] = ""
        result["pe_structure_parse_ok"] = 0
        return result

    try:
        fh = pe.FILE_HEADER
        oh = pe.OPTIONAL_HEADER

        # -- basic PE header fields ---------------------------------------
        dos_e_lfanew = _safe_int(pe.DOS_HEADER, "e_lfanew")
        coff_number_of_sections = _safe_int(fh, "NumberOfSections")
        raw_ts = _safe_int(fh, "TimeDateStamp")
        coff_timestamp_year = timestamp_to_year(raw_ts) or 0
        coff_number_of_symbols = _safe_int(fh, "NumberOfSymbols")
        coff_size_of_optional_header = _safe_int(fh, "SizeOfOptionalHeader")
        machine = f"0x{int(fh.Machine):04x}"
        characteristics = int(fh.Characteristics)
        is_dll = _safe_flag(0x2000, characteristics)
        is_executable_image = 0 if is_dll else 1
        optional_magic = f"0x{int(oh.Magic):04x}"
        is_pe32_plus = 1 if int(oh.Magic) == 0x20B else 0
        subsystem = f"0x{int(oh.Subsystem):04x}"

        # DLL Characteristics flags
        dll_chars = _safe_int(oh, "DllCharacteristics")
        relocations_stripped = _safe_flag(0x0001, characteristics)
        large_address_aware = _safe_flag(0x0020, characteristics)
        dynamic_base_aslr = _safe_flag(0x0040, dll_chars)
        nx_compatible = _safe_flag(0x0100, dll_chars)
        control_flow_guard = _safe_flag(0x4000, dll_chars)
        high_entropy_va = _safe_flag(0x0020, dll_chars)
        force_integrity = _safe_flag(0x0080, dll_chars)
        terminal_server_aware = _safe_flag(0x8000, dll_chars)

        # Timestamp flags
        timestamp_zero = 1 if raw_ts == 0 else 0
        timestamp_implausible = 0 if (raw_ts == 0 or is_plausible_timestamp(raw_ts)) else 1

        # Symbols
        symbol_table_present = 1 if coff_number_of_symbols > 0 else 0
        checksum_val = _safe_int(oh, "CheckSum")
        checksum_zero = 1 if checksum_val == 0 else 0

        # Version fields
        linker_major_version = _safe_int(oh, "MajorLinkerVersion")
        linker_minor_version = _safe_int(oh, "MinorLinkerVersion")
        os_major_version = _safe_int(oh, "MajorOperatingSystemVersion")
        os_minor_version = _safe_int(oh, "MinorOperatingSystemVersion")
        image_major_version = _safe_int(oh, "MajorImageVersion")
        image_minor_version = _safe_int(oh, "MinorImageVersion")
        subsystem_major_version = _safe_int(oh, "MajorSubsystemVersion")
        subsystem_minor_version = _safe_int(oh, "MinorSubsystemVersion")

        # Sizes
        size_of_code = _safe_int(oh, "SizeOfCode")
        size_of_initialized_data = _safe_int(oh, "SizeOfInitializedData")
        size_of_uninitialized_data = _safe_int(oh, "SizeOfUninitializedData")
        size_of_image = _safe_int(oh, "SizeOfImage")
        size_of_headers = _safe_int(oh, "SizeOfHeaders")
        entry_point_rva = _safe_int(oh, "AddressOfEntryPoint")
        entry_point_relative = (entry_point_rva / size_of_image) if size_of_image else 0.0
        image_base = _safe_int(oh, "ImageBase")
        section_alignment = _safe_int(oh, "SectionAlignment")
        file_alignment = _safe_int(oh, "FileAlignment")
        number_of_rva_and_sizes = _safe_int(oh, "NumberOfRvaAndSizes")

        # Ratios
        headers_to_image_ratio = (size_of_headers / size_of_image) if size_of_image else 0.0
        code_to_image_ratio = (size_of_code / size_of_image) if size_of_image else 0.0
        initialized_data_to_image_ratio = (
            size_of_initialized_data / size_of_image
        ) if size_of_image else 0.0

        # Stack / heap
        stack_reserve = _safe_int(oh, "SizeOfStackReserve")
        stack_commit = _safe_int(oh, "SizeOfStackCommit")
        heap_reserve = _safe_int(oh, "SizeOfHeapReserve")
        heap_commit = _safe_int(oh, "SizeOfHeapCommit")

        # Directories
        directories = list(getattr(oh, "DATA_DIRECTORY", []))
        directory_sizes: dict[int, int] = {}
        directory_present: dict[int, int] = {}
        for idx in range(16):
            if idx < len(directories):
                item = directories[idx]
                va = int(item.VirtualAddress) if item.VirtualAddress else 0
                sz = int(item.Size) if item.Size else 0
                directory_sizes[idx] = sz
                directory_present[idx] = 1 if (va and sz) else 0
            else:
                directory_sizes[idx] = 0
                directory_present[idx] = 0

        # --- sections ----------------------------------------------------
        sections = list(pe.sections)
        sec_names: list[str] = []
        section_rows: list[dict[str, Any]] = []
        entry_section_index = -1
        entry_entropy_val: float | None = None

        for i, section in enumerate(sections):
            raw = section.get_data()
            ent = entropy(raw)
            name = clean_section_name(section.Name)
            characteristics_s = int(section.Characteristics)
            raw_size = int(section.SizeOfRawData)
            virtual_size = max(int(section.Misc_VirtualSize), raw_size)
            start = int(section.VirtualAddress)
            executable = bool(characteristics_s & 0x20000000)
            writable = bool(characteristics_s & 0x80000000)
            readable = bool(characteristics_s & 0x40000000)

            if virtual_size and start <= entry_point_rva < start + virtual_size:
                entry_section_index = i
                entry_entropy_val = ent

            sec_names.append(name)
            section_rows.append({
                "name": name,
                "entropy": ent,
                "raw_size": raw_size,
                "virtual_size": virtual_size,
                "executable": executable,
                "writable": writable,
                "readable": readable,
            })

        # Section derived fields
        total_raw = sum(r["raw_size"] for r in section_rows)
        total_virtual = sum(r["virtual_size"] for r in section_rows)
        max_raw = max((r["raw_size"] for r in section_rows), default=0)
        max_virtual = max((r["virtual_size"] for r in section_rows), default=0)
        executable_count = sum(r["executable"] for r in section_rows)
        writable_count = sum(r["writable"] for r in section_rows)
        rwx_count = sum(r["readable"] and r["writable"] and r["executable"] for r in section_rows)
        zero_raw_count = sum(r["raw_size"] == 0 for r in section_rows)
        nonstandard_count = sum(0 if is_common_section_name(n) else 1 for n in sec_names)
        empty_count = sum(1 for n in sec_names if n == "")
        entropies = [r["entropy"] for r in section_rows]
        nonzero_entropies = [e for e in entropies if e > 0] or [0.0]
        high_entropy_count = sum(1 for e in entropies if e >= 7.0)

        entry_sec = section_rows[entry_section_index] if entry_section_index >= 0 else None

        # --- imports -----------------------------------------------------
        try:
            pe.parse_data_directories(directories=[1])  # import table
        except Exception:
            pass
        imports = getattr(pe, "DIRECTORY_ENTRY_IMPORT", [])
        import_dll_count = len(imports)
        import_symbol_count = sum(len(getattr(e, "imports", [])) for e in imports)
        ordinal_import_count = sum(
            sum(1 for imp in getattr(e, "imports", []) if getattr(imp, "name", None) is None)
            for e in imports
        )

        # --- exports -----------------------------------------------------
        exports = getattr(getattr(pe, "DIRECTORY_ENTRY_EXPORT", None), "symbols", [])
        export_symbol_count = len(exports)

        # --- resources ---------------------------------------------------
        resources = getattr(pe, "DIRECTORY_ENTRY_RESOURCE", None)
        resource_leafs = resource_leaf_count(resources) if resources else 0

        # --- debug -------------------------------------------------------
        debug_entries = getattr(pe, "DIRECTORY_ENTRY_DEBUG", [])
        debug_entry_count = len(debug_entries)

        # --- overlay -----------------------------------------------------
        overlay_start = pe.get_overlay_data_start_offset() or len(data)
        overlay_size = len(data) - overlay_start if overlay_start else 0

        # --- packing detection -------------------------------------------
        packing_detected = detect_packing(
            data, sec_names,
            [r["entropy"] for r in section_rows],
            entry_sec["executable"] if entry_sec else False,
            entry_point_rva,
        )

        # --- assemble result dict ----------------------------------------

        # ---- continuous features ----
        result.update({
            "file_size": len(data),
            "file_entropy": entropy(data),
            "dos_e_lfanew": dos_e_lfanew,
            "coff_number_of_sections": coff_number_of_sections,
            "coff_timestamp_year": coff_timestamp_year,
            "coff_number_of_symbols": coff_number_of_symbols,
            "coff_size_of_optional_header": coff_size_of_optional_header,
            "linker_major_version": linker_major_version,
            "linker_minor_version": linker_minor_version,
            "os_major_version": os_major_version,
            "os_minor_version": os_minor_version,
            "image_major_version": image_major_version,
            "image_minor_version": image_minor_version,
            "subsystem_major_version": subsystem_major_version,
            "subsystem_minor_version": subsystem_minor_version,
            "size_of_code": size_of_code,
            "size_of_initialized_data": size_of_initialized_data,
            "size_of_uninitialized_data": size_of_uninitialized_data,
            "entry_point_rva": entry_point_rva,
            "entry_point_relative": entry_point_relative,
            "image_base": image_base,
            "section_alignment": section_alignment,
            "file_alignment": file_alignment,
            "size_of_image": size_of_image,
            "size_of_headers": size_of_headers,
            "headers_to_image_ratio": headers_to_image_ratio,
            "code_to_image_ratio": code_to_image_ratio,
            "initialized_data_to_image_ratio": initialized_data_to_image_ratio,
            "checksum": checksum_val,
            "number_of_rva_and_sizes": number_of_rva_and_sizes,
            "stack_reserve": stack_reserve,
            "stack_commit": stack_commit,
            "heap_reserve": heap_reserve,
            "heap_commit": heap_commit,
            "section_total_raw_size": total_raw,
            "section_total_virtual_size": total_virtual,
            "section_max_raw_size": max_raw,
            "section_max_virtual_size": max_virtual,
            "executable_section_count": executable_count,
            "writable_section_count": writable_count,
            "rwx_section_count": rwx_count,
            "zero_raw_section_count": zero_raw_count,
            "nonstandard_section_name_count": nonstandard_count,
            "empty_section_name_count": empty_count,
            "entry_section_index": entry_section_index,
            "entry_section_raw_size": entry_sec["raw_size"] if entry_sec else 0,
            "entry_section_virtual_size": entry_sec["virtual_size"] if entry_sec else 0,
            "section_entropy_mean": sum(nonzero_entropies) / len(nonzero_entropies),
            "section_entropy_max": max(entropies) if entropies else 0.0,
            "entry_section_entropy": entry_entropy_val if entry_entropy_val is not None else 0.0,
            "high_entropy_section_count": high_entropy_count,
            "overlay_size": overlay_size,
            "import_dll_count": import_dll_count,
            "import_symbol_count": import_symbol_count,
            "ordinal_import_count": ordinal_import_count,
            "export_symbol_count": export_symbol_count,
            "resource_leaf_count": resource_leafs,
            "debug_entry_count": debug_entry_count,
        })
        for idx, name in DIRECTORY_NAMES.items():
            result[f"directory_{name}_size"] = directory_sizes.get(idx, 0)

        # ---- binary features ----
        has_rwx_section = 1 if rwx_count > 0 else 0
        result.update({
            "packing_detected": int(packing_detected),
            "is_pe32_plus": is_pe32_plus,
            "is_dll": is_dll,
            "is_executable_image": is_executable_image,
            "relocations_stripped": relocations_stripped,
            "large_address_aware": large_address_aware,
            "timestamp_zero": timestamp_zero,
            "timestamp_implausible": timestamp_implausible,
            "symbol_table_present": symbol_table_present,
            "checksum_zero": checksum_zero,
            "dynamic_base_aslr": dynamic_base_aslr,
            "nx_compatible": nx_compatible,
            "control_flow_guard": control_flow_guard,
            "high_entropy_va": high_entropy_va,
            "force_integrity": force_integrity,
            "terminal_server_aware": terminal_server_aware,
            "entry_point_in_section": 1 if entry_section_index >= 0 else 0,
            "entry_section_executable": int(entry_sec["executable"]) if entry_sec else 0,
            "entry_section_writable": int(entry_sec["writable"]) if entry_sec else 0,
            "entry_section_rwx": (
                1 if entry_sec and entry_sec["readable"] and entry_sec["writable"] and entry_sec["executable"]
                else 0
            ),
            "has_rwx_section": has_rwx_section,
            "has_nonstandard_section_name": 1 if nonstandard_count > 0 else 0,
            "has_empty_section_name": 1 if empty_count > 0 else 0,
            "has_high_entropy_section": 1 if high_entropy_count > 0 else 0,
            "has_overlay": 1 if overlay_size > 0 else 0,
            "has_imports": 1 if import_dll_count > 0 else 0,
            "has_exports": 1 if export_symbol_count > 0 else 0,
            "has_resources": 1 if resource_leafs > 0 else 0,
            "has_ordinal_import": 1 if ordinal_import_count > 0 else 0,
            "pe_structure_parse_ok": pe_structure_parse_ok,
        })
        for idx, name in DIRECTORY_NAMES.items():
            result[f"directory_{name}_present"] = directory_present.get(idx, 0)

        # ---- categorical features ----
        result.update({
            "machine": machine,
            "optional_magic": optional_magic,
            "subsystem": subsystem,
            "entry_section_name": entry_sec["name"] if entry_sec else "",
        })

    finally:
        pe.close()

    return result


# ---------------------------------------------------------------------------
# I/O helpers
# ---------------------------------------------------------------------------

def load_dataset(csv_path: Path) -> list[dict[str, str]]:
    """Load labeled samples from dataset.csv."""
    with csv_path.open("r", newline="", encoding="utf-8-sig") as handle:
        return [
            row for row in csv.DictReader(handle)
            if row.get("label") in {"0", "1"}
        ]


def write_csv(path: Path, rows: list[dict[str, Any]], fields: list[str]) -> None:
    with path.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


# ---------------------------------------------------------------------------
# Plotting
# ---------------------------------------------------------------------------

LABEL_NAMES = {0: "benign", 1: "malware"}
LABEL_COLORS = {0: "#2ecc71", 1: "#e74c3c"}

# Binary feature groups for split prevalence charts
BINARY_GROUPS: dict[str, list[str]] = {
    "PE Header Flags": [
        "is_pe32_plus", "is_dll", "is_executable_image",
        "relocations_stripped", "large_address_aware",
        "timestamp_zero", "timestamp_implausible",
        "symbol_table_present", "checksum_zero",
    ],
    "Security & Mitigation": [
        "dynamic_base_aslr", "nx_compatible", "control_flow_guard",
        "high_entropy_va", "force_integrity", "terminal_server_aware",
        "packing_detected",
    ],
    "Section & Entry Point": [
        "entry_point_in_section", "entry_section_executable",
        "entry_section_writable", "entry_section_rwx",
        "has_rwx_section", "has_nonstandard_section_name",
        "has_empty_section_name", "has_high_entropy_section",
    ],
    "Content & Resources": [
        "has_overlay", "has_imports", "has_exports", "has_resources",
        "has_ordinal_import", "pe_structure_parse_ok",
    ],
    "Data Directories": [f"directory_{name}_present" for name in DIRECTORY_NAMES.values()],
}


def _prevalence(frame: pd.DataFrame, columns: list[str]) -> dict[str, dict[int, float]]:
    """Compute per-label prevalence for a list of binary columns."""
    result: dict[str, dict[int, float]] = {}
    for col in columns:
        if col not in frame.columns:
            continue
        result[col] = {}
        for lbl in sorted(frame["label"].unique()):
            subset = frame.loc[frame["label"] == lbl, col]
            result[col][lbl] = float(subset.mean()) if len(subset) else 0.0
    return result


def _draw_prevalence_panel(ax: Any, cols: list[str], prevalence: dict, title: str) -> None:
    """Draw one prevalence bar-chart panel on a given Axes."""
    existing = [c for c in cols if c in prevalence]
    if not existing:
        ax.text(0.5, 0.5, "(no data)", ha="center", va="center", transform=ax.transAxes)
        ax.set_title(title, fontsize=10)
        return
    # Sort by absolute difference
    def _diff(c: str) -> float:
        vals = prevalence[c]
        return abs(vals.get(0, 0) - vals.get(1, 0)) if len(vals) >= 2 else 0
    ordered = sorted(existing, key=_diff, reverse=True)

    labels_sorted = sorted(prevalence[ordered[0]].keys())
    n_items = len(ordered)
    height = 0.35
    y = np.arange(n_items)
    for i, lbl in enumerate(labels_sorted):
        vals = [prevalence[c].get(lbl, 0) for c in ordered]
        ax.barh(y + i * height, vals, height,
                label=LABEL_NAMES.get(lbl, str(lbl)),
                color=LABEL_COLORS.get(lbl, "#888"), alpha=0.75)
    ax.set_yticks(y + height * (len(labels_sorted) - 1) / 2)
    ax.set_yticklabels(ordered, fontsize=7)
    ax.set_xlim(0, 1)
    ax.set_title(title, fontsize=10)
    ax.grid(axis="x", alpha=0.2)


def plot_binary_prevalence_split(frame: pd.DataFrame, output_dir: Path) -> None:
    """4-panel split binary prevalence chart (one figure, readable)."""
    groups = [(k, v) for k, v in BINARY_GROUPS.items()]
    prevalence_all = _prevalence(frame, [c for _, cols in groups for c in cols])

    # Layout: 2 cols for the first 4 groups, 1 wide row for Data Directories
    fig = plt.figure(figsize=(18, 20))
    # Top 4 panels in 2x2
    for i, (title, cols) in enumerate(groups[:4]):
        ax = fig.add_subplot(4, 2, i * 2 + 1 if i < 2 else (i - 2) * 2 + 6)
        _draw_prevalence_panel(ax, cols, prevalence_all, title)
    # Data Directories spans the bottom half (cols 1+2)
    ax_dir = fig.add_subplot(2, 1, 2)
    title_dd, cols_dd = groups[4]
    _draw_prevalence_panel(ax_dir, cols_dd, prevalence_all, title_dd)

    fig.legend([LABEL_NAMES[0], LABEL_NAMES[1]], loc="upper right",
               bbox_to_anchor=(0.99, 0.99), fontsize=10)
    fig.suptitle("Binary Feature Prevalence — Benign vs Malware (training set)",
                 fontsize=14, y=1.01)
    fig.tight_layout()
    fig.savefig(output_dir / "binary_prevalence.png", dpi=200, bbox_inches="tight")
    plt.close(fig)
    print(f"  binary_prevalence.png ({len(prevalence_all)} binary features in 5 groups)")


def plot_correlation_heatmap(frame: pd.DataFrame, output_dir: Path) -> None:
    """Correlation heatmap of top 20 continuous features (sorted by variance)."""
    cont_cols = [c for c in CONTINUOUS_FEATURES if c in frame.columns]
    # Pick top 20 by std
    stds = {c: frame[c].std() for c in cont_cols if frame[c].dtype in ("float64", "int64", "float32", "int32")}
    top = sorted(stds, key=lambda c: abs(stds[c]), reverse=True)[:20]
    corr = frame[top].corr()

    fig, ax = plt.subplots(figsize=(14, 12))
    im = ax.imshow(corr, cmap="RdBu_r", vmin=-1, vmax=1, aspect="auto")
    ax.set_xticks(range(len(top)))
    ax.set_xticklabels(top, rotation=90, fontsize=7)
    ax.set_yticks(range(len(top)))
    ax.set_yticklabels(top, fontsize=7)
    # Annotate with correlation values
    for i in range(len(top)):
        for j in range(len(top)):
            val = corr.iloc[i, j]
            color = "white" if abs(val) > 0.6 else "black"
            ax.text(j, i, f"{val:.2f}", ha="center", va="center", fontsize=5.5, color=color)
    fig.colorbar(im, ax=ax, shrink=0.8)
    ax.set_title("Correlation Heatmap — Top 20 Continuous Features (training set)", fontsize=12)
    fig.tight_layout()
    fig.savefig(output_dir / "correlation_heatmap.png", dpi=200, bbox_inches="tight")
    plt.close(fig)
    print(f"  correlation_heatmap.png (top {len(top)} features)")


def plot_cohens_d_ranking(frame: pd.DataFrame, output_dir: Path) -> None:
    """Cohen's d ranking: how well each continuous feature separates benign vs malware."""
    cont_cols = [c for c in CONTINUOUS_FEATURES if c in frame.columns
                 and frame[c].dtype in ("float64", "int64", "float32", "int32")]
    d_values: dict[str, float] = {}
    for col in cont_cols:
        g0 = frame.loc[frame["label"] == 0, col].dropna()
        g1 = frame.loc[frame["label"] == 1, col].dropna()
        if len(g0) < 3 or len(g1) < 3:
            continue
        m0, m1 = g0.mean(), g1.mean()
        s0, s1 = g0.std(), g1.std()
        pooled_std = math.sqrt((s0 ** 2 + s1 ** 2) / 2)
        d_values[col] = abs((m1 - m0) / pooled_std) if pooled_std > 0 else 0.0

    sorted_items = sorted(d_values.items(), key=lambda x: abs(x[1]), reverse=True)
    names = [item[0] for item in sorted_items]
    values = [item[1] for item in sorted_items]
    colors_bar = ["#e74c3c" if v > 0.5 else ("#f39c12" if v > 0.2 else "#95a5a6") for v in values]

    fig, ax = plt.subplots(figsize=(10, max(9, len(names) * 0.3)))
    ax.barh(range(len(names)), values, color=colors_bar, alpha=0.8)
    ax.set_yticks(range(len(names)))
    ax.set_yticklabels(names, fontsize=7)
    ax.invert_yaxis()
    ax.axvline(x=0.5, color="red", linestyle="--", alpha=0.5, label="|d|=0.5 (medium)")
    ax.axvline(x=0.2, color="orange", linestyle="--", alpha=0.5, label="|d|=0.2 (small)")
    ax.set_xlabel("|Cohen's d|")
    ax.set_title("Feature Discrimination Power — |Cohen's d| ranking (training set)")
    ax.legend(fontsize=8)
    ax.grid(axis="x", alpha=0.2)
    fig.tight_layout()
    fig.savefig(output_dir / "cohens_d_ranking.png", dpi=200, bbox_inches="tight")
    plt.close(fig)
    print(f"  cohens_d_ranking.png ({len(d_values)} features)")


def plot_categorical_breakdown(frame: pd.DataFrame, output_dir: Path) -> None:
    """Bar charts: machine type, subsystem, optional_magic distribution by label."""
    cat_features = ["machine", "subsystem", "optional_magic"]
    fig, axes = plt.subplots(1, 3, figsize=(16, 5))
    for ax, feat in zip(axes, cat_features):
        if feat not in frame.columns:
            ax.set_visible(False)
            continue
        # Count per label & value
        counts = frame.groupby([feat, "label"]).size().unstack(fill_value=0)
        # Top 8 values by total count
        totals = counts.sum(axis=1).sort_values(ascending=False)
        top_vals = totals.head(8).index
        plot_df = counts.loc[counts.index.isin(top_vals)]
        plot_df = plot_df.reindex(top_vals)
        x = np.arange(len(plot_df))
        width = 0.35
        for i, lbl in enumerate(sorted(frame["label"].unique())):
            vals = plot_df[lbl].values if lbl in plot_df.columns else np.zeros(len(plot_df))
            ax.bar(x + i * width, vals, width,
                   label=LABEL_NAMES.get(lbl, str(lbl)),
                   color=LABEL_COLORS.get(lbl, "#888"), alpha=0.75)
        ax.set_xticks(x + width / 2)
        ax.set_xticklabels(plot_df.index, rotation=45, ha="right", fontsize=7)
        ax.set_title(feat, fontsize=10)
        ax.legend(fontsize=7)
        ax.grid(axis="y", alpha=0.2)
    fig.suptitle("Categorical Feature Distribution — Benign vs Malware (training set)", fontsize=12)
    fig.tight_layout()
    fig.savefig(output_dir / "categorical_breakdown.png", dpi=200, bbox_inches="tight")
    plt.close(fig)
    print("  categorical_breakdown.png (machine, subsystem, optional_magic)")


def plot_top_scatter_pairs(frame: pd.DataFrame, output_dir: Path) -> None:
    """Scatter matrix of the 4 most discriminative continuous features."""
    cont_cols = [c for c in CONTINUOUS_FEATURES if c in frame.columns
                 and frame[c].dtype in ("float64", "int64")]
    # Compute Cohen's d to find top 4
    d_vals: dict[str, float] = {}
    for col in cont_cols:
        g0 = frame.loc[frame["label"] == 0, col].dropna()
        g1 = frame.loc[frame["label"] == 1, col].dropna()
        if len(g0) < 3 or len(g1) < 3:
            continue
        m0, m1 = g0.mean(), g1.mean()
        s0, s1 = g0.std(), g1.std()
        pooled = math.sqrt((s0 ** 2 + s1 ** 2) / 2)
        d_vals[col] = abs((m1 - m0) / pooled) if pooled > 0 else 0
    top4 = sorted(d_vals, key=lambda c: d_vals[c], reverse=True)[:4]

    n = len(top4)
    fig, axes = plt.subplots(n, n, figsize=(12, 11))
    for i, fy in enumerate(top4):
        for j, fx in enumerate(top4):
            ax = axes[i][j] if n > 1 else axes
            if i == j:
                # Diagonal: histogram
                for lbl in sorted(frame["label"].unique()):
                    vals = frame.loc[frame["label"] == lbl, fx].dropna()
                    ax.hist(vals, bins=30, alpha=0.4, density=True,
                            label=LABEL_NAMES.get(lbl, str(lbl)),
                            color=LABEL_COLORS.get(lbl, "#888"))
            else:
                for lbl in sorted(frame["label"].unique()):
                    subset = frame[frame["label"] == lbl]
                    ax.scatter(subset[fx], subset[fy], s=2, alpha=0.3,
                               color=LABEL_COLORS.get(lbl, "#888"),
                               label=LABEL_NAMES.get(lbl, str(lbl)))
                ax.set_xscale("symlog", linthresh=1)
                ax.set_yscale("symlog", linthresh=1)
            if j == 0:
                ax.set_ylabel(fy, fontsize=7)
            if i == n - 1:
                ax.set_xlabel(fx, fontsize=7)
            ax.tick_params(labelsize=6)
    handles = [plt.Line2D([0], [0], color=LABEL_COLORS[l], marker='o', linestyle='',
                          markersize=6, label=LABEL_NAMES[l])
               for l in sorted(frame["label"].unique())]
    fig.legend(handles=handles, loc="upper right", bbox_to_anchor=(0.99, 0.99), fontsize=8)
    fig.suptitle("Top 4 Discriminative Feature Pairs — Scatter Matrix (training set)", fontsize=12)
    fig.tight_layout()
    fig.savefig(output_dir / "top_scatter_pairs.png", dpi=200, bbox_inches="tight")
    plt.close(fig)
    print(f"  top_scatter_pairs.png ({', '.join(top4)})")


def plot_continuous_boxplots(frame: pd.DataFrame, output_dir: Path) -> None:
    """Box plots: 12 key continuous features, benign vs malware."""
    n = len(PLOT_CONTINUOUS)
    cols = 4
    rows_val = math.ceil(n / cols)
    fig, axes = plt.subplots(rows_val, cols, figsize=(cols * 3.5, rows_val * 3))
    for idx, feature in enumerate(PLOT_CONTINUOUS):
        ax = axes[idx // cols][idx % cols] if rows_val > 1 else axes[idx % cols]
        groups = [
            frame.loc[frame["label"] == lbl, feature].dropna().replace([np.inf, -np.inf], np.nan).dropna().values
            for lbl in sorted(frame["label"].unique())
        ]
        if all(len(g) for g in groups):
            bp = ax.boxplot(groups, tick_labels=[LABEL_NAMES.get(l, str(l)) for l in sorted(frame["label"].unique())],
                            patch_artist=True)
            for patch, lbl in zip(bp["boxes"], sorted(frame["label"].unique())):
                patch.set_facecolor(LABEL_COLORS.get(lbl, "#888"))
                patch.set_alpha(0.6)
        ax.set_title(textwrap.fill(feature, 22), fontsize=9)
        ax.tick_params(labelsize=7)
        ax.grid(axis="y", alpha=0.2)
    for idx in range(n, rows_val * cols):
        ax = axes[idx // cols][idx % cols] if rows_val > 1 else axes[idx]
        ax.set_visible(False)
    fig.suptitle("Continuous Features — Benign vs Malware (training set)", fontsize=12, y=1.01)
    fig.tight_layout()
    fig.savefig(output_dir / "continuous_distributions.png", dpi=200, bbox_inches="tight")
    plt.close(fig)
    print(f"  continuous_distributions.png ({n} features)")


def plot_entropy_histograms(frame: pd.DataFrame, output_dir: Path) -> None:
    """Overlaid histograms of entropy/overlay features, colored by label."""
    features = [
        "file_entropy", "section_entropy_mean", "section_entropy_max",
        "entry_section_entropy", "overlay_size", "high_entropy_section_count",
    ]
    fig, axes = plt.subplots(2, 3, figsize=(13, 8))
    for ax, feat in zip(axes.ravel(), features):
        for lbl in sorted(frame["label"].unique()):
            vals = frame.loc[frame["label"] == lbl, feat].dropna().replace([np.inf, -np.inf], np.nan).dropna()
            if len(vals):
                ax.hist(vals, bins=40, alpha=0.4, label=LABEL_NAMES.get(lbl, str(lbl)),
                        color=LABEL_COLORS.get(lbl, "#888"), density=True)
        ax.set_title(textwrap.fill(feat, 22), fontsize=9)
        ax.legend(fontsize=7)
        ax.tick_params(labelsize=7)
        ax.grid(axis="y", alpha=0.2)
    fig.suptitle("Entropy & Overlay Distributions — Benign vs Malware (training set)", fontsize=12)
    fig.tight_layout()
    fig.savefig(output_dir / "entropy_features.png", dpi=200, bbox_inches="tight")
    plt.close(fig)
    print(f"  entropy_features.png ({len(features)} features)")


def plot_directory_presence_heatmap(frame: pd.DataFrame, output_dir: Path) -> None:
    """Heatmap: directory presence rate by label for all 16 data directories."""
    dir_cols = [f"directory_{name}_present" for name in DIRECTORY_NAMES.values()]
    dir_cols = [c for c in dir_cols if c in frame.columns]
    data = []
    for lbl in sorted(frame["label"].unique()):
        row = [float(frame.loc[frame["label"] == lbl, c].mean()) for c in dir_cols]
        data.append(row)
    data_arr = np.array(data)
    fig, ax = plt.subplots(figsize=(10, 2.5))
    im = ax.imshow(data_arr, cmap="YlOrRd", vmin=0, vmax=1, aspect="auto")
    ax.set_xticks(range(len(dir_cols)))
    ax.set_xticklabels([c.replace("directory_", "").replace("_present", "") for c in dir_cols],
                       rotation=45, ha="right", fontsize=8)
    ax.set_yticks(range(len(LABEL_NAMES)))
    ax.set_yticklabels([LABEL_NAMES[l] for l in sorted(frame["label"].unique())], fontsize=9)
    for i in range(data_arr.shape[0]):
        for j in range(data_arr.shape[1]):
            ax.text(j, i, f"{data_arr[i, j]:.2f}", ha="center", va="center", fontsize=7)
    fig.colorbar(im, ax=ax, shrink=0.9)
    ax.set_title("Data Directory Presence Rate by Label (training set)", fontsize=11)
    fig.tight_layout()
    fig.savefig(output_dir / "directory_presence.png", dpi=200, bbox_inches="tight")
    plt.close(fig)
    print("  directory_presence.png")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--csv", type=Path, default=Path("dataset.csv"))
    parser.add_argument("--output-dir", type=Path, default=Path("pe_statistics"))
    parser.add_argument("--limit", type=int)
    parser.add_argument(
        "--train-ratio", type=float, default=0.7,
        help="Fraction of samples per label to use for training (default: 0.7)",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    rows = load_dataset(args.csv)
    if args.limit is not None:
        rows = rows[:args.limit]

    # --- Split per-label: first train_ratio for training set ---
    label_groups: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in rows:
        label_groups[row["label"]].append(row)

    split_info: dict[str, dict[str, int]] = {}
    train_rows: list[dict[str, str]] = []
    for label, group in label_groups.items():
        cutoff = int(len(group) * args.train_ratio)
        split_info[label] = {"total": len(group), "train": cutoff, "rest": len(group) - cutoff}
        train_rows.extend(group[:cutoff])
    rows = train_rows
    label_name_map = {"0": "benign", "1": "malware"}
    print(
        f"Train ratio: {args.train_ratio:.0%} | "
        + " | ".join(
            f"{label_name_map.get(l, l)}={info['total']} -> "
            f"train={info['train']}, rest={info['rest']}"
            for l, info in split_info.items()
        )
    )

    # --- Extract features ---
    metadata_fields = ["sha256", "source", "label", "analysis_variant", "analysis_sha256"]
    output_fields = metadata_fields + ALL_FEATURES

    feature_rows: list[dict[str, Any]] = []
    failures: list[dict[str, str]] = []
    for index, row in enumerate(rows, 1):
        sha256 = row["sha256"].lower()
        file_path = Path(row["path"])
        try:
            data = file_path.read_bytes()
            actual_sha256 = sha256_bytes(data)
            if actual_sha256 != sha256:
                raise ValueError(f"SHA256 mismatch: expected {sha256}, got {actual_sha256}")
            values = extract_features(data)
            feature_rows.append({
                "sha256": sha256,
                "source": row.get("source", ""),
                "label": int(row["label"]),
                "analysis_variant": "original",
                "analysis_sha256": actual_sha256,
                **values,
            })
            status = "PE/ok"
        except Exception as exc:
            failures.append({
                "sha256": sha256,
                "path": row.get("path", ""),
                "reason": f"{type(exc).__name__}: {exc}",
            })
            status = "failed"
        if index % 100 == 0 or index == 1 or index == len(rows):
            print(f"[{index}/{len(rows)}] {sha256}: {status}")

    if not feature_rows:
        raise RuntimeError("No labeled PE samples were parsed")

    # --- Write output ---
    args.output_dir.mkdir(parents=True, exist_ok=True)
    frame = pd.DataFrame(feature_rows)

    # Main feature CSV
    frame.to_csv(args.output_dir / "sample_features.csv", index=False, encoding="utf-8-sig")
    print(f"\nWrote {len(frame)} rows × {len(frame.columns)} columns to sample_features.csv")

    # Failures
    write_csv(args.output_dir / "failures.csv", failures, ["sha256", "path", "reason"])
    print(f"Wrote {len(failures)} failures to failures.csv")

    # Summary statistics
    summary = (
        frame.groupby(["label"])[CONTINUOUS_FEATURES]
        .agg(["count", "mean", "median", "std"])
    )
    summary.columns = [f"{feat}_{stat}" for feat, stat in summary.columns]
    summary.reset_index().to_csv(
        args.output_dir / "summary.csv", index=False, encoding="utf-8-sig"
    )
    print("Wrote summary.csv")

    # --- Plots ---
    print("\nGenerating plots...")
    plot_continuous_boxplots(frame, args.output_dir)
    plot_binary_prevalence_split(frame, args.output_dir)
    plot_entropy_histograms(frame, args.output_dir)
    plot_correlation_heatmap(frame, args.output_dir)
    plot_cohens_d_ranking(frame, args.output_dir)
    plot_categorical_breakdown(frame, args.output_dir)
    plot_top_scatter_pairs(frame, args.output_dir)
    plot_directory_presence_heatmap(frame, args.output_dir)

    print(f"\nDone — all output in {args.output_dir}/")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
