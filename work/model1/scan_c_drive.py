"""Scan C:\ drive PE files with model, save results incrementally."""

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
THRESHOLD = 0.3
MODEL_PATH = Path("pe_model_output_no_debug/model.joblib")

# Only exclude the specified dirs (none are on C:\, so this is just for safety)
EXCLUDE_DIRS = [
    r"e:\StudyFiles\project\yukiho\maldataset",
    r"e:\StudyFiles\project\yukiho\virussharedownloader",
    r"e:\StudyFiles\project\PE-traceRAG",
    r"e:\StudyFiles\malware",
]
EXCLUDE_DIRS_NORM = [os.path.normpath(d).casefold() for d in EXCLUDE_DIRS]

PE_EXTENSIONS = {".exe", ".dll", ".sys", ".ocx", ".scr", ".cpl", ".drv", ".bin", ".efi", ".com"}

OUTPUT_CSV = Path("pe_model_output_no_debug/scan_c_results.csv")
FAILURES_CSV = Path("pe_model_output_no_debug/scan_c_failures.csv")
SAVE_INTERVAL = 500  # flush to disk every N predictions

# ---------------------------------------------------------------------------
def is_excluded(path: str) -> bool:
    norm = os.path.normpath(path).casefold()
    for excl in EXCLUDE_DIRS_NORM:
        if norm == excl or norm.startswith(excl + os.sep):
            return True
    return False


def main():
    print("=" * 70)
    print("PE Malware Scanner — C: Drive Only")
    print(f"Started: {datetime.now(timezone.utc).isoformat()}")
    print(f"Model: {MODEL_PATH}  |  Threshold: {THRESHOLD}")
    print("=" * 70)

    print("\n[1] Loading model...", flush=True)
    model = joblib.load(MODEL_PATH)
    print(f"  {type(model).__name__} loaded.", flush=True)

    # Prepare output files
    OUTPUT_CSV.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = ["path", "malware_probability", "prediction", "file_size",
                  "section_entropy_max", "timestamp_raw"]

    # Write CSV header
    with OUTPUT_CSV.open("w", newline="", encoding="utf-8-sig") as f:
        csv.DictWriter(f, fieldnames=fieldnames).writeheader()
    with FAILURES_CSV.open("w", newline="", encoding="utf-8-sig") as f:
        csv.DictWriter(f, fieldnames=["path", "reason"]).writeheader()

    # Scan
    print("\n[2] Scanning C:\\ ...", flush=True)
    results_buf = []
    failures_buf = []
    scanned = 0
    predicted = 0
    failed = 0
    start = time.perf_counter()

    for root, dirs, files in os.walk("C:\\", topdown=True, followlinks=False):
        dirs[:] = [d for d in dirs if not is_excluded(os.path.join(root, d))]
        if is_excluded(root):
            dirs.clear()
            continue

        for fname in files:
            ext = os.path.splitext(fname)[1].casefold()
            if ext not in PE_EXTENSIONS:
                continue

            filepath = os.path.join(root, fname)
            scanned += 1

            try:
                features = extract_features(Path(filepath))
                X = pd.DataFrame(
                    [{name: features[name] for name in MODEL_FEATURES}],
                    columns=MODEL_FEATURES,
                )
                prob = float(model.predict_proba(X)[0, 1])
                results_buf.append({
                    "path": filepath,
                    "malware_probability": prob,
                    "prediction": int(prob >= THRESHOLD),
                    "file_size": features.get("audit_file_size", 0),
                    "section_entropy_max": features.get("audit_section_entropy_max", 0),
                    "timestamp_raw": features.get("audit_timestamp_raw", 0),
                })
                predicted += 1
            except Exception as e:
                failures_buf.append({"path": filepath, "reason": f"{type(e).__name__}: {e}"})
                failed += 1

            # Flush buffer to disk periodically
            if len(results_buf) >= SAVE_INTERVAL:
                with OUTPUT_CSV.open("a", newline="", encoding="utf-8-sig") as f:
                    csv.DictWriter(f, fieldnames=fieldnames).writerows(results_buf)
                results_buf.clear()
            if len(failures_buf) >= SAVE_INTERVAL:
                with FAILURES_CSV.open("a", newline="", encoding="utf-8-sig") as f:
                    csv.DictWriter(f, fieldnames=["path", "reason"]).writerows(failures_buf)
                failures_buf.clear()

            if scanned % 200 == 0:
                elapsed = time.perf_counter() - start
                rate = scanned / elapsed if elapsed > 0 else 0
                print(f"  Scanned: {scanned} | Predicted: {predicted} | "
                      f"Failed: {failed} | Rate: {rate:.0f} files/s", flush=True)

    # Flush remaining
    if results_buf:
        with OUTPUT_CSV.open("a", newline="", encoding="utf-8-sig") as f:
            csv.DictWriter(f, fieldnames=fieldnames).writerows(results_buf)
    if failures_buf:
        with FAILURES_CSV.open("a", newline="", encoding="utf-8-sig") as f:
            csv.DictWriter(f, fieldnames=["path", "reason"]).writerows(failures_buf)

    elapsed = time.perf_counter() - start
    print(f"\n  Done C:\\. Scanned: {scanned} | Predicted: {predicted} | "
          f"Failed: {failed} | Time: {elapsed:.0f}s", flush=True)

    # Now read back all results and sort by probability
    print("\n[3] Reading & sorting results...", flush=True)
    all_results = []
    with OUTPUT_CSV.open("r", encoding="utf-8-sig") as f:
        for r in csv.DictReader(f):
            r["malware_probability"] = float(r["malware_probability"])
            r["prediction"] = int(r["prediction"])
            all_results.append(r)

    all_results.sort(key=lambda r: r["malware_probability"], reverse=True)

    # Rewrite sorted
    with OUTPUT_CSV.open("w", newline="", encoding="utf-8-sig") as f:
        csv.DictWriter(f, fieldnames=fieldnames).writerows(all_results)

    # Summary
    malware_hits = [r for r in all_results if r["prediction"] == 1]
    print("\n" + "=" * 70)
    print("SUMMARY — C: Drive")
    print("=" * 70)
    print(f"  Total scanned:   {scanned}")
    print(f"  Predicted:       {predicted}")
    print(f"  Failures:        {failed}")
    print(f"  Malware (p>={THRESHOLD}): {len(malware_hits)}")
    print(f"  Benign:          {len(all_results) - len(malware_hits)}")

    # Probability distribution
    probs = [r["malware_probability"] for r in all_results]
    print(f"\n  Probability distribution:")
    for lo, hi, label in [(0, 0.1, "0.0-0.1"), (0.1, 0.3, "0.1-0.3"),
                           (0.3, 0.5, "0.3-0.5"), (0.5, 0.7, "0.5-0.7"),
                           (0.7, 0.9, "0.7-0.9"), (0.9, 1.0, "0.9-1.0")]:
        count = sum(1 for p in probs if lo <= p < hi)
        print(f"    {label}: {count}")

    # Top malware hits
    if malware_hits:
        print(f"\n  Top 40 malware detections:")
        print(f"  {'Path':<105} {'Prob':>8}")
        print(f"  {'-'*105} {'-'*8}")
        for r in malware_hits[:40]:
            path_display = r["path"]
            if len(path_display) > 103:
                path_display = "..." + path_display[-100:]
            print(f"  {path_display:<105} {r['malware_probability']:>8.6f}")

    print(f"\n  Sorted results: {OUTPUT_CSV.resolve()}")
    print(f"  Failures:       {FAILURES_CSV.resolve()}")
    print("Done.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
