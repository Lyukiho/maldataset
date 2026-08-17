#!/usr/bin/env python3
"""Audit and non-destructively repair disarmed BODMAS PE headers.

BODMAS malware binaries have the COFF Machine field cleared and usually have
the Optional Header Subsystem field cleared.  A zero Machine value prevents
some headless disassemblers/decompilers from selecting an x86 processor.

This tool repairs Machine in a copied file:

* PE32  (Optional Header magic 0x10B) -> IMAGE_FILE_MACHINE_I386  (0x014C)
* PE32+ (Optional Header magic 0x20B) -> IMAGE_FILE_MACHINE_AMD64 (0x8664)

Subsystem is preserved by default because its original value cannot be
recovered from a disarmed binary.  It can be set explicitly for compatibility,
but the generated manifest marks that value as synthetic.

Original samples are never modified.  Files are written through a .part file
and atomically renamed after repair.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import csv
import hashlib
import os
import re
import shutil
import struct
import sys
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable, Mapping, Sequence


DOS_MAGIC = b"MZ"
PE_MAGIC = b"PE\0\0"
PE32_MAGIC = 0x10B
PE32_PLUS_MAGIC = 0x20B
IMAGE_FILE_MACHINE_I386 = 0x014C
IMAGE_FILE_MACHINE_AMD64 = 0x8664
SUBSYSTEM_OFFSET_IN_OPTIONAL_HEADER = 68
MAX_PE_HEADER_OFFSET = 16 * 1024 * 1024
SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")


class PEFormatError(ValueError):
    """Raised when a file does not contain a minimally valid PE header."""


@dataclass(frozen=True)
class PEHeader:
    pe_offset: int
    optional_magic: int
    machine_offset: int
    machine: int
    inferred_machine: int
    subsystem_offset: int
    subsystem: int

    @property
    def pe_kind(self) -> str:
        return "PE32" if self.optional_magic == PE32_MAGIC else "PE32+"


@dataclass(frozen=True)
class Sample:
    dataset_sha256: str
    family: str
    size_bytes: int
    batch_id: str
    idx_in_batch: int
    timestamp: str = ""


@dataclass(frozen=True)
class RepairRecord:
    dataset_sha256: str
    input_sha256: str
    repaired_sha256: str
    family: str
    timestamp: str
    batch_id: str
    idx_in_batch: int
    size_bytes: int
    pe_kind: str
    original_machine: str
    repaired_machine: str
    machine_inference: str
    original_subsystem: int
    repaired_subsystem: int
    subsystem_synthetic: bool
    status: str
    source_path: str
    output_path: str


REPAIR_FIELDS = [field.name for field in RepairRecord.__dataclass_fields__.values()]


def read_exact_at(handle, offset: int, length: int) -> bytes:
    handle.seek(offset)
    data = handle.read(length)
    if len(data) != length:
        raise PEFormatError(
            f"truncated file at offset 0x{offset:x}: expected {length} bytes, got {len(data)}"
        )
    return data


def inspect_pe(path: Path) -> PEHeader:
    file_size = path.stat().st_size
    with path.open("rb") as handle:
        dos = read_exact_at(handle, 0, 64)
        if dos[:2] != DOS_MAGIC:
            raise PEFormatError("missing MZ signature")

        pe_offset = struct.unpack_from("<I", dos, 0x3C)[0]
        if pe_offset > MAX_PE_HEADER_OFFSET or pe_offset + 24 > file_size:
            raise PEFormatError(f"invalid PE header offset 0x{pe_offset:x}")

        coff = read_exact_at(handle, pe_offset, 24)
        if coff[:4] != PE_MAGIC:
            raise PEFormatError("missing PE signature")

        machine = struct.unpack_from("<H", coff, 4)[0]
        optional_size = struct.unpack_from("<H", coff, 20)[0]
        required_optional_size = SUBSYSTEM_OFFSET_IN_OPTIONAL_HEADER + 2
        if optional_size < required_optional_size:
            raise PEFormatError(
                f"optional header too small: {optional_size} < {required_optional_size}"
            )

        optional_offset = pe_offset + 24
        optional = read_exact_at(handle, optional_offset, required_optional_size)
        optional_magic = struct.unpack_from("<H", optional, 0)[0]
        if optional_magic == PE32_MAGIC:
            inferred_machine = IMAGE_FILE_MACHINE_I386
        elif optional_magic == PE32_PLUS_MAGIC:
            inferred_machine = IMAGE_FILE_MACHINE_AMD64
        else:
            raise PEFormatError(f"unsupported Optional Header magic 0x{optional_magic:04x}")

        subsystem = struct.unpack_from(
            "<H", optional, SUBSYSTEM_OFFSET_IN_OPTIONAL_HEADER
        )[0]

    return PEHeader(
        pe_offset=pe_offset,
        optional_magic=optional_magic,
        machine_offset=pe_offset + 4,
        machine=machine,
        inferred_machine=inferred_machine,
        subsystem_offset=optional_offset + SUBSYSTEM_OFFSET_IN_OPTIONAL_HEADER,
        subsystem=subsystem,
    )


def parse_batch_spec(spec: str) -> set[str]:
    """Parse values such as '1-5,8,batch_10' into batch directory names."""
    result: set[str] = set()
    for raw_part in spec.split(","):
        part = raw_part.strip().lower().removeprefix("batch_")
        if not part:
            continue
        if "-" in part:
            start_text, end_text = part.split("-", 1)
            start, end = int(start_text), int(end_text)
            if start <= 0 or end < start:
                raise argparse.ArgumentTypeError(f"invalid batch range: {raw_part}")
            result.update(f"batch_{number}" for number in range(start, end + 1))
        else:
            number = int(part)
            if number <= 0:
                raise argparse.ArgumentTypeError(f"invalid batch number: {raw_part}")
            result.add(f"batch_{number}")
    if not result:
        raise argparse.ArgumentTypeError("batch selection is empty")
    return result


def load_metadata(path: Path | None) -> Mapping[str, Mapping[str, str]]:
    if path is None:
        return {}
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        rows = csv.DictReader(handle)
        required = {"sha", "timestamp", "family"}
        if not rows.fieldnames or not required.issubset(rows.fieldnames):
            raise ValueError(f"metadata must contain columns {sorted(required)}")
        return {row["sha"].strip().lower(): row for row in rows}


def load_samples(
    manifest_path: Path,
    batches: set[str],
    metadata_path: Path | None,
    limit: int | None,
) -> list[Sample]:
    metadata = load_metadata(metadata_path)
    samples: list[Sample] = []
    with manifest_path.open("r", encoding="utf-8-sig", newline="") as handle:
        rows = csv.DictReader(handle)
        required = {"sha", "family", "size_bytes", "batch_id", "idx_in_batch"}
        if not rows.fieldnames or not required.issubset(rows.fieldnames):
            raise ValueError(f"manifest must contain columns {sorted(required)}")
        for row in rows:
            if row["batch_id"] not in batches:
                continue
            dataset_sha = row["sha"].strip().lower()
            if not SHA256_RE.fullmatch(dataset_sha):
                raise ValueError(f"invalid SHA-256 in manifest: {dataset_sha!r}")
            meta = metadata.get(dataset_sha, {})
            manifest_family = row["family"].strip()
            metadata_family = (meta.get("family") or "").strip()
            if metadata_family and metadata_family.lower() != manifest_family.lower():
                raise ValueError(f"family mismatch for {dataset_sha}")
            samples.append(
                Sample(
                    dataset_sha256=dataset_sha,
                    family=manifest_family,
                    size_bytes=int(row["size_bytes"]),
                    batch_id=row["batch_id"],
                    idx_in_batch=int(row["idx_in_batch"]),
                    timestamp=(meta.get("timestamp") or "").strip(),
                )
            )
    samples.sort(key=lambda sample: (int(sample.batch_id.split("_")[1]), sample.idx_in_batch))
    return samples[:limit] if limit is not None else samples


def sample_path(root: Path, sample: Sample) -> Path:
    return root / sample.batch_id / f"{sample.dataset_sha256}.exe"


def hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(4 * 1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def copy_with_hash(source: Path, destination: Path) -> str:
    digest = hashlib.sha256()
    with source.open("rb") as src, destination.open("wb") as dst:
        while chunk := src.read(4 * 1024 * 1024):
            digest.update(chunk)
            dst.write(chunk)
    return digest.hexdigest()


def patch_copy(
    sample: Sample,
    source_root: Path,
    output_root: Path,
    subsystem: int | None,
    overwrite: bool,
) -> RepairRecord:
    source = sample_path(source_root, sample)
    output = sample_path(output_root, sample)
    part = output.with_name(output.name + ".part")

    if not source.is_file():
        raise FileNotFoundError(source)
    actual_size = source.stat().st_size
    if actual_size != sample.size_bytes:
        raise ValueError(
            f"source size mismatch for {source}: manifest={sample.size_bytes}, actual={actual_size}"
        )

    header = inspect_pe(source)
    if header.machine not in (0, header.inferred_machine):
        raise PEFormatError(
            f"Machine 0x{header.machine:04x} conflicts with {header.pe_kind} inference "
            f"0x{header.inferred_machine:04x}: {source}"
        )

    repaired_subsystem = header.subsystem if subsystem is None else subsystem
    synthetic_subsystem = subsystem is not None and subsystem != header.subsystem
    output.parent.mkdir(parents=True, exist_ok=True)

    status = "repaired"
    if output.exists() and not overwrite:
        existing = inspect_pe(output)
        if (
            output.stat().st_size == sample.size_bytes
            and existing.machine == header.inferred_machine
            and existing.subsystem == repaired_subsystem
        ):
            input_sha = hash_file(source)
            repaired_sha = hash_file(output)
            status = "existing_verified"
            return make_record(
                sample, header, repaired_subsystem, synthetic_subsystem,
                input_sha, repaired_sha, status, source, output
            )
        raise FileExistsError(f"output exists and is not the requested repair: {output}")

    if part.exists():
        part.unlink()
    try:
        input_sha = copy_with_hash(source, part)
        with part.open("r+b") as handle:
            handle.seek(header.machine_offset)
            handle.write(struct.pack("<H", header.inferred_machine))
            if subsystem is not None:
                handle.seek(header.subsystem_offset)
                handle.write(struct.pack("<H", subsystem))
            handle.flush()
            os.fsync(handle.fileno())
        shutil.copystat(source, part)
        repaired_sha = hash_file(part)
        os.replace(part, output)
    except BaseException:
        if part.exists():
            part.unlink()
        raise

    return make_record(
        sample, header, repaired_subsystem, synthetic_subsystem,
        input_sha, repaired_sha, status, source, output
    )


def make_record(
    sample: Sample,
    header: PEHeader,
    repaired_subsystem: int,
    synthetic_subsystem: bool,
    input_sha: str,
    repaired_sha: str,
    status: str,
    source: Path,
    output: Path,
) -> RepairRecord:
    return RepairRecord(
        dataset_sha256=sample.dataset_sha256,
        input_sha256=input_sha,
        repaired_sha256=repaired_sha,
        family=sample.family,
        timestamp=sample.timestamp,
        batch_id=sample.batch_id,
        idx_in_batch=sample.idx_in_batch,
        size_bytes=sample.size_bytes,
        pe_kind=header.pe_kind,
        original_machine=f"0x{header.machine:04x}",
        repaired_machine=f"0x{header.inferred_machine:04x}",
        machine_inference="optional_header_magic",
        original_subsystem=header.subsystem,
        repaired_subsystem=repaired_subsystem,
        subsystem_synthetic=synthetic_subsystem,
        status=status,
        source_path=str(source),
        output_path=str(output),
    )


def audit(samples: Sequence[Sample], root: Path) -> int:
    counts: Counter[str] = Counter()
    errors: list[tuple[Path, str]] = []
    for sample in samples:
        path = sample_path(root, sample)
        try:
            if path.stat().st_size != sample.size_bytes:
                counts["size_mismatch"] += 1
                continue
            header = inspect_pe(path)
            counts[f"kind_{header.pe_kind}"] += 1
            counts[f"machine_0x{header.machine:04x}"] += 1
            counts[f"subsystem_{header.subsystem}"] += 1
            if header.machine == 0:
                counts["needs_machine_repair"] += 1
            elif header.machine == header.inferred_machine:
                counts["machine_already_usable"] += 1
            else:
                counts["machine_conflict"] += 1
        except (OSError, PEFormatError, ValueError) as exc:
            counts["error"] += 1
            errors.append((path, str(exc)))

    print(f"Audited {len(samples)} samples")
    for key, value in sorted(counts.items()):
        print(f"{key}: {value}")
    for path, message in errors[:20]:
        print(f"ERROR {path}: {message}", file=sys.stderr)
    if len(errors) > 20:
        print(f"... {len(errors) - 20} more errors", file=sys.stderr)
    return 1 if errors or counts["machine_conflict"] or counts["size_mismatch"] else 0


def write_repair_manifest(path: Path, records: Iterable[RepairRecord]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    merged: dict[tuple[str, str], dict[str, object]] = {}
    if path.exists():
        with path.open("r", encoding="utf-8-sig", newline="") as handle:
            reader = csv.DictReader(handle)
            if reader.fieldnames == REPAIR_FIELDS:
                for row in reader:
                    merged[(row["batch_id"], row["dataset_sha256"])] = row
    for record in records:
        row = asdict(record)
        merged[(record.batch_id, record.dataset_sha256)] = row

    ordered = sorted(
        merged.values(),
        key=lambda row: (int(str(row["batch_id"]).split("_")[1]), int(row["idx_in_batch"])),
    )
    part = path.with_name(path.name + ".part")
    with part.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=REPAIR_FIELDS)
        writer.writeheader()
        writer.writerows(ordered)
    os.replace(part, path)


def repair(
    samples: Sequence[Sample],
    source_root: Path,
    output_root: Path,
    subsystem: int | None,
    workers: int,
    overwrite: bool,
) -> int:
    if source_root.resolve() == output_root.resolve():
        raise ValueError("source and output roots must be different")

    print(
        f"Repairing {len(samples)} samples into {output_root} "
        f"with {workers} worker(s); subsystem="
        f"{'preserve' if subsystem is None else subsystem}"
    )
    records: list[RepairRecord] = []
    failures: list[tuple[Sample, str]] = []

    def task(sample: Sample) -> RepairRecord:
        return patch_copy(sample, source_root, output_root, subsystem, overwrite)

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        future_to_sample = {executor.submit(task, sample): sample for sample in samples}
        for completed, future in enumerate(concurrent.futures.as_completed(future_to_sample), 1):
            sample = future_to_sample[future]
            try:
                records.append(future.result())
            except Exception as exc:  # continue so the failure report is complete
                failures.append((sample, str(exc)))
            if completed % 100 == 0 or completed == len(samples):
                print(
                    f"progress: {completed}/{len(samples)}, "
                    f"ok={len(records)}, failed={len(failures)}",
                    flush=True,
                )

    records.sort(key=lambda row: (int(row.batch_id.split("_")[1]), row.idx_in_batch))
    write_repair_manifest(output_root / "repair_manifest.csv", records)
    if failures:
        failure_path = output_root / "repair_failures.csv"
        with failure_path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(
                handle,
                fieldnames=["dataset_sha256", "batch_id", "idx_in_batch", "error"],
            )
            writer.writeheader()
            for sample, message in failures:
                writer.writerow(
                    {
                        "dataset_sha256": sample.dataset_sha256,
                        "batch_id": sample.batch_id,
                        "idx_in_batch": sample.idx_in_batch,
                        "error": message,
                    }
                )
        print(f"Repair finished with {len(failures)} failure(s): {failure_path}")
        return 1
    failure_path = output_root / "repair_failures.csv"
    if failure_path.exists():
        failure_path.unlink()
    print(f"Repair complete: {output_root / 'repair_manifest.csv'}")
    return 0


def subsystem_value(text: str) -> int | None:
    normalized = text.strip().lower()
    aliases = {"preserve": None, "gui": 2, "console": 3}
    if normalized in aliases:
        return aliases[normalized]
    value = int(normalized, 0)
    if not 0 <= value <= 0xFFFF:
        raise argparse.ArgumentTypeError("subsystem must fit in an unsigned 16-bit value")
    return value


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "command", choices=("audit", "repair"), help="audit inputs or create repaired copies"
    )
    parser.add_argument("--root", type=Path, required=True, help="source dataset root")
    parser.add_argument(
        "--manifest",
        type=Path,
        help="batch manifest (default: ROOT/batch_manifest.csv)",
    )
    parser.add_argument(
        "--metadata",
        type=Path,
        help="optional original bodmas_metadata.csv used to add timestamps",
    )
    parser.add_argument(
        "--batches", type=parse_batch_spec, default=parse_batch_spec("1-5"),
        help="batch selection, e.g. 1-5,8 (default: 1-5)",
    )
    parser.add_argument("--limit", type=int, help="process only the first N selected samples")
    parser.add_argument("--output-root", type=Path, help="required for repair")
    parser.add_argument(
        "--subsystem", type=subsystem_value, default=None,
        help="preserve (default), gui/2, console/3, or another numeric value",
    )
    parser.add_argument("--workers", type=int, default=4, help="copy worker count (default: 4)")
    parser.add_argument("--overwrite", action="store_true", help="replace conflicting output files")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.limit is not None and args.limit <= 0:
        raise SystemExit("--limit must be positive")
    if args.workers <= 0:
        raise SystemExit("--workers must be positive")

    root = args.root.resolve()
    manifest = (args.manifest or root / "batch_manifest.csv").resolve()
    metadata = args.metadata.resolve() if args.metadata else None
    samples = load_samples(manifest, args.batches, metadata, args.limit)
    if not samples:
        raise SystemExit("no samples matched the requested batches")

    if args.command == "audit":
        return audit(samples, root)
    if args.output_root is None:
        raise SystemExit("--output-root is required for repair")
    return repair(
        samples=samples,
        source_root=root,
        output_root=args.output_root.resolve(),
        subsystem=args.subsystem,
        workers=args.workers,
        overwrite=args.overwrite,
    )


if __name__ == "__main__":
    raise SystemExit(main())
