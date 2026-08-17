"""Scan all PE files across drives, predict malware probability with trained model.

Excludes specified directories. Saves results sorted by malware probability.
"""

from __future__ import annotations

import csv
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import joblib
import pandas as pd

from pe_feature_model import extract_features, MODEL_FEATURES

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
THRESHOLD = 0.3
MODEL_PATH = Path("pe_model_output_no_debug/model.joblib")

# Directories to exclude (normalized, case-insensitive on Windows)
EXCLUDE_DIRS = [
    r"e:\StudyFiles\project\yukiho\maldataset",
    r"e:\StudyFiles\project\yukiho\virussharedownloader",
    r"e:\StudyFiles\project\PE-traceRAG",
    r"e:\StudyFiles\malware",
]
EXCLUDE_DIRS_NORM = [os.path.normpath(d).casefold() for d in EXCLUDE_DIRS]

# Drives to scan
DRIVES = ["C:\\", "D:\\", "E:\\", "F:\\"]

# PE file extensions to scan
PE_EXTENSIONS = {".exe", ".dll", ".sys", ".ocx", ".scr", ".cpl", ".drv", ".bin", ".efi", ".com"}

# Output
OUTPUT_CSV = Path("pe_model_output_no_debug/scan_all_results.csv")
PROGRESS_INTERVAL = 100  # print progress every N files

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def is_excluded(path: str) -> bool:
    """Check if path is under any excluded directory."""
    norm = os.path.normpath(path).casefold()
    for excl in EXCLUDE_DIRS_NORM:
        if norm == excl or norm.startswith(excl + os.sep):
            return True
    return False


def iter_pe_files():
    """Walk all drives and yield PE file paths, skipping excluded dirs."""
    for drive in DRIVES:
        if not os.path.exists(drive):
            print(f"  Skipping missing drive: {drive}")
            continue
        print(f"  Walking {drive} ...")
        for root, dirs, files in os.walk(drive, topdown=True, followlinks=False):
            # Prune excluded directories in-place
            dirs[:] = [d for d in dirs if not is_excluded(os.path.join(root, d))]
            # Skip if current root itself is excluded
            if is_excluded(root):
                dirs.clear()
                continue
            for fname in files:
                ext = os.path.splitext(fname)[1].casefold()
                if ext in PE_EXTENSIONS:
                    full = os.path.join(root, fname)
                    if not is_excluded(full):
                        yield full


def get_file_sha256(path: str) -> str:
    """Compute SHA-256 of file. Returns empty string on error."""
    import hashlib
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return ""


def main():
    print("=" * 70)
    print("PE Malware Scanner — All Drives")
    print(f"Started: {datetime.now(timezone.utc).isoformat()}")
    print(f"Model: {MODEL_PATH}")
    print(f"Threshold: {THRESHOLD}")
    print(f"Excluded dirs: {len(EXCLUDE_DIRS_NORM)}")
    for d in EXCLUDE_DIRS_NORM:
        print(f"  - {d}")
    print("=" * 70)

    # Load model
    print("\n[1] Loading model...")
    model = joblib.load(MODEL_PATH)
    print(f"  Model loaded: {type(model).__name__}")

    # Scan and predict
    print("\n[2] Scanning and predicting...")
    results = []
    failures = []
    scanned = 0
    predicted = 0
    start = time.perf_counter()

    for filepath in iter_pe_files():
        scanned += 1
        try:
            features = extract_features(Path(filepath))
            X = pd.DataFrame(
                [{name: features[name] for name in MODEL_FEATURES}],
                columns=MODEL_FEATURES,
            )
            prob = float(model.predict_proba(X)[0, 1])
            prediction = int(prob >= THRESHOLD)
            results.append({
                "path": filepath,
                "malware_probability": prob,
                "prediction": prediction,
                "file_size": features.get("audit_file_size", 0),
                "section_entropy_max": features.get("audit_section_entropy_max", 0),
                "timestamp_raw": features.get("audit_timestamp_raw", 0),
            })
            predicted += 1
        except Exception as e:
            failures.append({"path": filepath, "reason": f"{type(e).__name__}: {e}"})

        if scanned % PROGRESS_INTERVAL == 0:
            elapsed = time.perf_counter() - start
            rate = scanned / elapsed if elapsed > 0 else 0
            print(f"  Scanned: {scanned} | Predicted: {predicted} | "
                  f"Failed: {len(failures)} | Rate: {rate:.0f} files/s")

    elapsed = time.perf_counter() - start
    print(f"\n  Done. Scanned: {scanned} | Predicted: {predicted} | "
          f"Failed: {len(failures)} | Time: {elapsed:.0f}s")

    # Sort by malware probability descending
    results.sort(key=lambda r: r["malware_probability"], reverse=True)

    # Save results
    print(f"\n[3] Saving results to {OUTPUT_CSV}...")
    OUTPUT_CSV.parent.mkdir(parents=True, exist_ok=True)
    with OUTPUT_CSV.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "path", "malware_probability", "prediction", "file_size",
            "section_entropy_max", "timestamp_raw",
        ])
        writer.writeheader()
        writer.writerows(results)

    # Save failures
    if failures:
        fail_path = OUTPUT_CSV.with_name("scan_all_failures.csv")
        with fail_path.open("w", newline="", encoding="utf-8-sig") as f:
            writer = csv.DictWriter(f, fieldnames=["path", "reason"])
            writer.writeheader()
            writer.writerows(failures)
        print(f"  Failures saved to {fail_path}")

    # Summary
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print(f"  Total files scanned: {scanned}")
    print(f"  Successfully predicted: {predicted}")
    print(f"  Extraction failures: {len(failures)}")

    malware_hits = [r for r in results if r["prediction"] == 1]
    print(f"  Malware detected (prob >= {THRESHOLD}): {len(malware_hits)}")
    print(f"  Benign: {len(results) - len(malware_hits)}")

    # Top malware hits
    if malware_hits:
        print(f"\n  Top 30 malware detections:")
        print(f"  {'Path':<100} {'Prob':>8}")
        print(f"  {'-'*100} {'-'*8}")
        for r in malware_hits[:30]:
            path_display = r["path"]
            if len(path_display) > 98:
                path_display = "..." + path_display[-95:]
            print(f"  {path_display:<100} {r['malware_probability']:>8.6f}")

    # Probability distribution
    if results:
        probs = [r["malware_probability"] for r in results]
        print(f"\n  Probability distribution:")
        for lo, hi, label in [(0, 0.1, "0.0-0.1"), (0.1, 0.3, "0.1-0.3"),
                               (0.3, 0.5, "0.3-0.5"), (0.5, 0.7, "0.5-0.7"),
                               (0.7, 0.9, "0.7-0.9"), (0.9, 1.0, "0.9-1.0")]:
            count = sum(1 for p in probs if lo <= p < hi)
            print(f"    {label}: {count}")

    print(f"\nFull results: {OUTPUT_CSV.resolve()}")
    print("Done.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
