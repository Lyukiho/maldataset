#!/usr/bin/env python3
"""Run the IDAPython extractor over a CSV selection with per-sample timeout."""

from __future__ import annotations

import argparse
import concurrent.futures
import csv
import os
import subprocess
import time
from pathlib import Path


def run_one(
    row: dict[str, str],
    ida: Path,
    extractor: Path,
    output_root: Path,
    timeout: int,
    max_functions: int,
    keep_database: bool,
) -> dict[str, object]:
    sha = row["dataset_sha256"]
    sample = Path(row.get("path") or row.get("output_path") or "")
    json_path = output_root / "json" / f"{sha}.json"
    error_path = json_path.with_name(json_path.name + ".error.json")
    database_path = output_root / "db" / f"{sha}.i64"
    log_path = output_root / "logs" / f"{sha}.log"
    started = time.time()

    if json_path.is_file() and json_path.stat().st_size > 0:
        return {
            "dataset_sha256": sha,
            "family": row.get("family", ""),
            "pilot_group": row.get("pilot_group", ""),
            "status": "existing",
            "exit_code": 0,
            "elapsed_seconds": 0.0,
            "json_path": str(json_path),
            "log_path": str(log_path),
            "error": "",
        }

    if error_path.exists():
        error_path.unlink()
    command = [
        str(ida),
        "-A",
        "-c",
        f"-o{database_path}",
        f"-L{log_path}",
        f"-S{extractor} {json_path} {max_functions}",
        str(sample),
    ]
    status = "ok"
    exit_code = 0
    error = ""
    try:
        completed = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout,
            check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        exit_code = completed.returncode
        if exit_code != 0 or not json_path.is_file():
            status = "failed"
            error = f"IDA exit={exit_code}, json_exists={json_path.is_file()}"
    except subprocess.TimeoutExpired:
        status = "timeout"
        exit_code = -1
        error = f"exceeded {timeout}s"
    except Exception as exc:
        status = "runner_error"
        exit_code = -2
        error = f"{type(exc).__name__}: {exc}"
    finally:
        if not keep_database and database_path.exists():
            database_path.unlink()

    return {
        "dataset_sha256": sha,
        "family": row.get("family", ""),
        "pilot_group": row.get("pilot_group", ""),
        "status": status,
        "exit_code": exit_code,
        "elapsed_seconds": round(time.time() - started, 3),
        "json_path": str(json_path),
        "log_path": str(log_path),
        "error": error,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ida", type=Path, required=True)
    parser.add_argument("--extractor", type=Path, required=True)
    parser.add_argument("--selection", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--timeout", type=int, default=180)
    parser.add_argument("--max-functions", type=int, default=48)
    parser.add_argument("--workers", type=int, default=1)
    parser.add_argument("--keep-database", action="store_true")
    args = parser.parse_args()

    ida = args.ida.resolve()
    extractor = args.extractor.resolve()
    output_root = args.output_root.resolve()
    for name in ("json", "db", "logs"):
        (output_root / name).mkdir(parents=True, exist_ok=True)
    with args.selection.open("r", encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.DictReader(handle))

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = {
            executor.submit(
                run_one, row, ida, extractor, output_root,
                args.timeout, args.max_functions, args.keep_database,
            ): row
            for row in rows
        }
        for index, future in enumerate(concurrent.futures.as_completed(futures), 1):
            result = future.result()
            results.append(result)
            print(
                f"{index}/{len(rows)} {result['dataset_sha256'][:12]} "
                f"{result['family']} {result['status']} {result['elapsed_seconds']}s",
                flush=True,
            )

    results.sort(key=lambda row: row["dataset_sha256"])
    report = output_root / "run_manifest.csv"
    part = report.with_name(report.name + ".part")
    with part.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(results[0]))
        writer.writeheader()
        writer.writerows(results)
    os.replace(part, report)
    failures = sum(row["status"] not in ("ok", "existing") for row in results)
    print(f"complete: samples={len(results)} failures={failures} report={report}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
