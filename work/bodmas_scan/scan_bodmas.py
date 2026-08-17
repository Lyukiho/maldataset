"""Scan the BODMAS malware dataset with the trained no-debug model.

Ground truth: every sample under D:\\bodmas_malware_dataset_batches_ida is malware.
Reports detection rate (recall) at the established threshold 0.3, plus the full
probability distribution. All outputs live in this directory — nothing is written
into model1/.
"""

from __future__ import annotations

import csv
import os
import sys
import time
from pathlib import Path

import joblib
import pandas as pd

# Import extract_features from model1/ without touching its output dirs.
MODEL1_DIR = Path(__file__).resolve().parent.parent / "model1"
sys.path.insert(0, str(MODEL1_DIR))
from pe_feature_model import extract_features  # noqa: E402

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
THRESHOLD = 0.3
MODEL_PATH = MODEL1_DIR / "pe_model_output_no_debug" / "model.joblib"
SCAN_ROOT = Path(r"D:\bodmas_malware_dataset_batches_ida")
OUTPUT_DIR = Path(__file__).resolve().parent
PE_EXTENSIONS = {".exe", ".dll", ".sys", ".ocx", ".scr", ".cpl", ".drv", ".bin", ".efi", ".com"}

# Feature set must match the no_debug ablation model exactly:
# debug_directory_present is dropped, and the debug bit (0b10) is cleared from
# directory_presence_pattern (same as training-time `& ~0b10`).
NUMERIC_FEATURES = [
    "section_entropy_max",
    "section_max_raw_size",
    "nonstandard_section_name_count",
    "standard_section_name_count",
    "user32_minus_crt_import_count",
    "entry_section_rwx",
    "embedded_payload_ratio",
    "timestamp_implausible",
    "checksum_zero",
]
CATEGORICAL_FEATURES = ["directory_presence_pattern"]
FEATURES = NUMERIC_FEATURES + CATEGORICAL_FEATURES
DEBUG_BIT = 0b10

RESULTS_CSV = OUTPUT_DIR / "bodmas_results.csv"
FAILURES_CSV = OUTPUT_DIR / "bodmas_failures.csv"
PROGRESS_INTERVAL = 200


def iter_pe_files():
    for root, dirs, files in os.walk(SCAN_ROOT, topdown=True, followlinks=False):
        for fname in files:
            if os.path.splitext(fname)[1].casefold() in PE_EXTENSIONS:
                yield os.path.join(root, fname)


def main() -> int:
    print("=" * 70)
    print("BODMAS Malware Scan — no_debug model")
    print(f"Model:   {MODEL_PATH}")
    print(f"Scan:    {SCAN_ROOT}")
    print(f"Threshold: {THRESHOLD}")
    print(f"Output:  {OUTPUT_DIR}")
    print("=" * 70)

    print("\n[1] Loading model...", flush=True)
    model = joblib.load(MODEL_PATH)
    print(f"  {type(model).__name__} loaded (model: {type(model.named_steps['model']).__name__})", flush=True)

    print("\n[2] Scanning and predicting...", flush=True)
    results = []
    failures = []
    scanned = 0
    predicted = 0
    start = time.perf_counter()

    for filepath in iter_pe_files():
        scanned += 1
        try:
            features = extract_features(Path(filepath))
            # Reproduce the no_debug training transformation on the categorical bitmask.
            dpp = int(features["directory_presence_pattern"]) & ~DEBUG_BIT
            row = {name: features[name] for name in NUMERIC_FEATURES}
            row["directory_presence_pattern"] = dpp
            X = pd.DataFrame([row], columns=FEATURES)
            prob = float(model.predict_proba(X)[0, 1])
            results.append({
                "path": filepath,
                "sha256": Path(filepath).stem.casefold(),
                "malware_probability": prob,
                "prediction": int(prob >= THRESHOLD),
                "file_size": features.get("audit_file_size", 0),
                "section_entropy_max": features.get("audit_section_entropy_max", 0),
            })
            predicted += 1
        except Exception as e:
            failures.append({"path": filepath, "reason": f"{type(e).__name__}: {e}"})

        if scanned % PROGRESS_INTERVAL == 0:
            elapsed = time.perf_counter() - start
            rate = scanned / elapsed if elapsed > 0 else 0
            print(f"  Scanned: {scanned} | Predicted: {predicted} | "
                  f"Failed: {len(failures)} | Rate: {rate:.0f} files/s", flush=True)

    elapsed = time.perf_counter() - start
    print(f"\n  Done. Scanned: {scanned} | Predicted: {predicted} | "
          f"Failed: {len(failures)} | Time: {elapsed:.0f}s", flush=True)

    results.sort(key=lambda r: r["malware_probability"], reverse=True)

    # Save results
    print(f"\n[3] Saving results...", flush=True)
    fieldnames = ["path", "sha256", "malware_probability", "prediction",
                  "file_size", "section_entropy_max"]
    with RESULTS_CSV.open("w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(results)

    if failures:
        with FAILURES_CSV.open("w", newline="", encoding="utf-8-sig") as f:
            w = csv.DictWriter(f, fieldnames=["path", "reason"])
            w.writeheader()
            w.writerows(failures)
        print(f"  Failures saved to {FAILURES_CSV.name}", flush=True)

    # Summary
    malware_hits = [r for r in results if r["prediction"] == 1]
    n = len(results)
    detection_rate = len(malware_hits) / n if n else 0.0
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print(f"  Total files scanned:  {scanned}")
    print(f"  Successfully parsed:  {predicted}")
    print(f"  Extraction failures:  {len(failures)}")
    print(f"  Detected as malware (p >= {THRESHOLD}): {len(malware_hits)} / {n}")
    print(f"  Detection rate (recall): {detection_rate:.4f}  "
          f"({detection_rate * 100:.2f}%)")
    print(f"  Missed (FN, p < {THRESHOLD}): {n - len(malware_hits)}")

    probs = [r["malware_probability"] for r in results]
    print(f"\n  Probability distribution:")
    for lo, hi, label in [(0, 0.1, "0.0-0.1"), (0.1, 0.3, "0.1-0.3"),
                          (0.3, 0.5, "0.3-0.5"), (0.5, 0.7, "0.5-0.7"),
                          (0.7, 0.9, "0.7-0.9"), (0.9, 1.0, "0.9-1.0")]:
        count = sum(1 for p in probs if lo <= p < hi)
        print(f"    {label}: {count}")

    if probs:
        import statistics
        print(f"\n  min={min(probs):.6f}  median={statistics.median(probs):.6f}  "
              f"mean={statistics.mean(probs):.6f}  max={max(probs):.6f}")

    # Lowest-confidence predictions (likely FN candidates)
    lowest = results[-20:][::-1]
    print(f"\n  20 lowest-confidence predictions:")
    for r in lowest:
        print(f"    [{r['malware_probability']:.6f}] {Path(r['path']).name}")

    print(f"\n  Results: {RESULTS_CSV.resolve()}")
    if failures:
        print(f"  Failures: {FAILURES_CSV.resolve()}")
    print("Done.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
