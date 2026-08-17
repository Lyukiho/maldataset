"""Train and evaluate PE classifiers using handcrafted features.

Reads dataset.csv, splits 60/40 per label, 5-fold CV on train, evaluate on test.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import math
import random
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import joblib

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import pefile
from sklearn.base import clone
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import ExtraTreesClassifier, HistGradientBoostingClassifier
from sklearn.inspection import permutation_importance
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    balanced_accuracy_score,
    confusion_matrix,
    f1_score,
    precision_recall_curve,
    precision_score,
    recall_score,
    roc_auc_score,
    roc_curve,
)
from sklearn.model_selection import StratifiedKFold
from sklearn.neural_network import MLPClassifier
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from sklearn.tree import DecisionTreeClassifier
from sklearn.utils.class_weight import compute_sample_weight

# ---------------------------------------------------------------------------
# Constants (from reference)
# ---------------------------------------------------------------------------
SEED = 20260725
HASH_RE = re.compile(r"^[0-9a-f]{64}$")

COMMON_SECTION_NAMES = {
    ".text", ".code", "code", ".data", "data", ".rdata", ".bss", "bss",
    ".idata", ".edata", ".pdata", ".xdata", ".sxdata", ".rsrc", ".reloc",
    ".tls", ".crt", ".debug", ".didat", ".gfids", ".giats", ".gljmp", ".00cfg",
}

DIRECTORY_PATTERN_BITS = (
    (0, "export"), (6, "debug"), (10, "load_config"),
    (2, "resource"), (5, "basereloc"), (9, "tls"),
)

DYNAMIC_LOAD_APIS = {
    "loadlibrarya", "loadlibraryw", "loadlibraryexa", "loadlibraryexw",
    "getprocaddress", "ldrloaddll",
}
FILE_OPEN_APIS = {
    "createfilea", "createfilew", "createfile2", "ntcreatefile", "zwcreatefile",
}
FILE_WRITE_APIS = {
    "writefile", "writefileex", "ntwritefile", "zwwritefile",
}

NUMERIC_FEATURES = [
    "section_entropy_max",
    "section_max_raw_size",
    "nonstandard_section_name_count",
    "standard_section_name_count",
    "user32_minus_crt_import_count",
    "debug_directory_present",
    "entry_section_rwx",
    "embedded_payload_ratio",
    "timestamp_implausible",
    "checksum_zero",
]
CATEGORICAL_FEATURES = [
    "directory_presence_pattern",
]
MODEL_FEATURES = NUMERIC_FEATURES + CATEGORICAL_FEATURES


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def byte_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    total = len(data)
    return -sum((c / total) * math.log2(c / total) for c in Counter(data).values())


def decode_ascii(value: bytes | None) -> str:
    return value.decode("ascii", errors="replace") if value else ""


def is_crt_dll(name: str) -> bool:
    n = name.casefold()
    return (
        n in {"msvcrt.dll", "ucrtbase.dll"}
        or n.startswith("api-ms-win-crt-")
        or bool(re.fullmatch(r"vcruntime\d*d?\.dll", n))
        or bool(re.fullmatch(r"msvcp\d*d?\.dll", n))
    )


def data_directory(dirs: list[Any], idx: int) -> Any | None:
    return dirs[idx] if idx < len(dirs) else None


def directory_present(dirs: list[Any], idx: int) -> bool:
    e = data_directory(dirs, idx)
    return bool(e is not None and int(e.VirtualAddress) and int(e.Size))


def non_certificate_overlay_stats(
    pe: pefile.PE, *, file_size: int, dirs: list[Any],
) -> tuple[int, int, int]:
    overlay_start = pe.get_overlay_data_start_offset()
    if overlay_start is None:
        return 0, 0, 0
    overlay_start = max(0, min(int(overlay_start), file_size))
    overlay_size = max(0, file_size - overlay_start)
    sec = data_directory(dirs, 4)
    cert_start = int(sec.VirtualAddress) if sec else 0
    cert_size = int(sec.Size) if sec else 0
    cert_end = cert_start + cert_size
    cert_overlap = max(0, min(file_size, cert_end) - max(overlay_start, cert_start))
    return overlay_size, cert_size, max(0, overlay_size - cert_overlap)


def _timestamp_to_year(ts: int) -> int | None:
    if ts <= 0:
        return None
    try:
        return datetime.fromtimestamp(ts, tz=timezone.utc).year
    except (OSError, OverflowError, ValueError):
        return None


# Linker major version → earliest plausible compilation year
# Covers MSVC, GNU ld (MinGW/Cygwin), and LLVM LLD (which reuses MSVC versions).
_LINKER_EARLIEST_YEAR: dict[int, int] = {
    2: 1995,   # GNU ld 2.x (MinGW / Cygwin)
    6: 1998,   # VC6
    7: 2002,   # VS .NET 2002
    8: 2005,   # VS 2005
    9: 2008,   # VS 2008
    10: 2010,  # VS 2010
    11: 2012,  # VS 2012
    12: 2013,  # VS 2013
    14: 2015,  # VS 2015 / 2017 / 2019 / 2022 (LLD also reports ~14)
    15: 2017,  # VS 2017+
}
_KNOWN_LINKER_MAJORS: set[int] = set(_LINKER_EARLIEST_YEAR.keys())


def is_linker_version_unknown(linker_major: int) -> int:
    return 0 if linker_major in _KNOWN_LINKER_MAJORS else 1


def is_timestamp_implausible(ts: int, linker_major: int) -> int:
    """Timestamp must not be after this year, nor before the linker was released.

    For unknown linkers the "before linker" check falls back to a basic 1990 floor.
    """
    year = _timestamp_to_year(ts)
    if year is None:
        return 0  # ts==0 is not "implausible", just absent
    this_year = datetime.now(timezone.utc).year
    if year > this_year:
        return 1
    earliest = _LINKER_EARLIEST_YEAR.get(linker_major, 1990)
    if year < earliest:
        return 1
    return 0


# ---------------------------------------------------------------------------
# Feature extraction (14 core features from reference)
# ---------------------------------------------------------------------------
def extract_features(path: Path) -> dict[str, Any]:
    pe = pefile.PE(str(path), fast_load=True)
    try:
        file_size = path.stat().st_size
        entry_rva = int(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
        sections: list[dict[str, Any]] = []
        entry_section: dict | None = None
        for section in pe.sections:
            name = decode_ascii(section.Name).rstrip("\0").strip().casefold()
            ch = int(section.Characteristics)
            va = int(section.VirtualAddress)
            vs = int(section.Misc_VirtualSize)
            rs = int(section.SizeOfRawData)
            span = max(vs, rs)
            item = {
                "name": name, "virtual_address": va, "virtual_size": vs,
                "raw_size": rs, "span": span,
                "entropy": byte_entropy(section.get_data()),
                "readable": bool(ch & 0x40000000),
                "writable": bool(ch & 0x80000000),
                "executable": bool(ch & 0x20000000),
            }
            sections.append(item)
            if entry_section is None and span > 0 and va <= entry_rva < va + span:
                entry_section = item

        sec_entropy_max = max((s["entropy"] for s in sections), default=0.0)
        sec_max_raw = max((s["raw_size"] for s in sections), default=0)
        sec_names = [s["name"] for s in sections]
        std_count = sum(bool(n) and n in COMMON_SECTION_NAMES for n in sec_names)
        nonstd_count = sum(bool(n) and n not in COMMON_SECTION_NAMES for n in sec_names)
        empty_count = sum(not n for n in sec_names)

        pe.parse_data_directories(directories=[1, 6])
        user32_cnt = 0
        crt_cnt = 0
        has_virtualalloc = False
        has_loadlibrarya = False
        imported_names: set[str] = set()
        for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
            dll = decode_ascii(entry.dll).casefold()
            names = [decode_ascii(imp.name).casefold() for imp in entry.imports if imp.name]
            imported_names.update(names)
            if dll == "user32.dll":
                user32_cnt += len(entry.imports)
            if is_crt_dll(dll):
                crt_cnt += len(entry.imports)
            if dll == "kernel32.dll":
                has_virtualalloc |= "virtualalloc" in names
                has_loadlibrarya |= "loadlibrarya" in names

        dirs = list(pe.OPTIONAL_HEADER.DATA_DIRECTORY)
        debug_present = directory_present(dirs, 6)
        resource = data_directory(dirs, 2)
        res_size = int(resource.Size) if resource and directory_present(dirs, 2) else 0
        _, _, non_cert_overlay = non_certificate_overlay_stats(pe, file_size=file_size, dirs=dirs)

        embedded_payload_ratio = (
            max(res_size, non_cert_overlay) / file_size if file_size else 0.0
        )

        # Payload handling pattern
        dyn_hits = sorted(imported_names & DYNAMIC_LOAD_APIS)
        f_open = sorted(imported_names & FILE_OPEN_APIS)
        f_write = sorted(imported_names & FILE_WRITE_APIS)
        has_dyn = bool(dyn_hits)
        has_fw = bool(f_open and f_write)
        if has_dyn and has_fw:
            payload_pattern = "both"
        elif has_dyn:
            payload_pattern = "dynamic_only"
        elif has_fw:
            payload_pattern = "write_only"
        else:
            payload_pattern = "none"

        # Directory presence pattern
        dir_mask = 0
        for bit, (di, _) in enumerate(DIRECTORY_PATTERN_BITS):
            if directory_present(dirs, di):
                dir_mask |= 1 << bit

        # Timestamp plausibility (linker-aware)
        raw_ts = int(pe.FILE_HEADER.TimeDateStamp)
        linker_major = int(pe.OPTIONAL_HEADER.MajorLinkerVersion)
        ts_implausible = is_timestamp_implausible(raw_ts, linker_major)
        linker_unknown = is_linker_version_unknown(linker_major)

        # Checksum
        checksum_val = int(pe.OPTIONAL_HEADER.CheckSum)
        checksum_zero = 1 if checksum_val == 0 else 0

        return {
            "section_entropy_max": sec_entropy_max,
            "section_max_raw_size": math.sqrt(max(0, sec_max_raw)),
            "nonstandard_section_name_count": nonstd_count,
            "standard_section_name_count": std_count,
            "user32_minus_crt_import_count": user32_cnt - crt_cnt,
            "imports_kernel32_virtualalloc": int(has_virtualalloc),
            "imports_kernel32_loadlibrarya": int(has_loadlibrarya),
            "debug_directory_present": int(debug_present),
            "entry_section_rwx": int(
                entry_section and entry_section["readable"]
                and entry_section["writable"] and entry_section["executable"]
            ),
            "embedded_payload_ratio": embedded_payload_ratio,
            "timestamp_implausible": ts_implausible,
            "linker_version_unknown": linker_unknown,
            "checksum_zero": checksum_zero,
            "payload_handling_pattern": payload_pattern,
            "directory_presence_pattern": dir_mask,
            # Audit fields
            "audit_section_entropy_max": sec_entropy_max,
            "audit_section_names": "|".join(sec_names),
            "audit_file_size": file_size,
            "audit_timestamp_raw": raw_ts,
            "audit_linker_major": linker_major,
            "audit_checksum": checksum_val,
        }
    finally:
        pe.close()


# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------
def load_dataset(csv_path: Path) -> list[dict[str, str]]:
    with csv_path.open("r", newline="", encoding="utf-8-sig") as f:
        return [r for r in csv.DictReader(f) if r.get("label") in {"0", "1"}]


# ---------------------------------------------------------------------------
# Model building
# ---------------------------------------------------------------------------
def make_preprocessor() -> ColumnTransformer:
    return ColumnTransformer(
        transformers=[
            ("numeric", StandardScaler(), NUMERIC_FEATURES),
            ("cat", OneHotEncoder(handle_unknown="ignore", sparse_output=False),
             CATEGORICAL_FEATURES),
        ],
        remainder="drop", verbose_feature_names_out=False,
    )


def build_models() -> dict[str, Pipeline]:
    estimators = {
        "logistic_regression": LogisticRegression(max_iter=2000, random_state=SEED),
        "decision_tree": DecisionTreeClassifier(max_depth=4, min_samples_leaf=5, random_state=SEED),
        "extra_trees": ExtraTreesClassifier(n_estimators=500, min_samples_leaf=2, random_state=SEED, n_jobs=1),
        "hist_gradient_boosting": HistGradientBoostingClassifier(
            learning_rate=0.05, max_iter=250, max_leaf_nodes=15,
            min_samples_leaf=10, l2_regularization=1.0, random_state=SEED,
        ),
        "small_mlp": MLPClassifier(
            hidden_layer_sizes=(16, 8), activation="relu", alpha=0.01,
            batch_size=32, learning_rate_init=0.001, max_iter=1500,
            early_stopping=True, validation_fraction=0.15, n_iter_no_change=40,
            random_state=SEED,
        ),
    }
    return {name: Pipeline([("preprocess", make_preprocessor()), ("model", est)])
            for name, est in estimators.items()}


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------
def classification_metrics(y_true: np.ndarray, preds: np.ndarray, probs: np.ndarray) -> dict:
    tn, fp, fn, tp = confusion_matrix(y_true, preds, labels=[0, 1]).ravel()
    specificity = tn / (tn + fp) if tn + fp else 0.0
    return {
        "n": len(y_true), "tp": int(tp), "tn": int(tn), "fp": int(fp), "fn": int(fn),
        "accuracy": accuracy_score(y_true, preds),
        "balanced_accuracy": balanced_accuracy_score(y_true, preds),
        "precision": precision_score(y_true, preds, zero_division=0),
        "recall": recall_score(y_true, preds, zero_division=0),
        "specificity": specificity,
        "f1": f1_score(y_true, preds, zero_division=0),
        "roc_auc": roc_auc_score(y_true, probs),
        "pr_auc": average_precision_score(y_true, probs),
    }


def cross_validate(models: dict[str, Pipeline], X: pd.DataFrame, y: np.ndarray, threshold: float = 0.5) -> pd.DataFrame:
    splitter = StratifiedKFold(n_splits=5, shuffle=True, random_state=SEED)
    rows = []
    for name, proto in models.items():
        for fold, (fit_idx, val_idx) in enumerate(splitter.split(X, y), 1):
            pipe = clone(proto)
            fit_y = y[fit_idx]
            w = compute_sample_weight(class_weight="balanced", y=fit_y)
            pipe.fit(X.iloc[fit_idx], fit_y, model__sample_weight=w)
            probs = pipe.predict_proba(X.iloc[val_idx])[:, 1]
            preds = (probs >= threshold).astype(int)
            rows.append({"model": name, "fold": fold, **classification_metrics(y[val_idx], preds, probs)})
    frame = pd.DataFrame(rows)
    metrics = ["accuracy", "balanced_accuracy", "precision", "recall", "specificity", "f1", "roc_auc", "pr_auc"]
    summary = frame.groupby("model")[metrics].agg(["mean", "std"])
    summary.columns = [f"{m}_{s}" for m, s in summary.columns]
    return summary.reset_index()


def evaluate_external(
    models: dict[str, Pipeline], X_train: pd.DataFrame, y_train: np.ndarray,
    X_test: pd.DataFrame, y_test: np.ndarray, threshold: float = 0.5,
) -> tuple[dict[str, Pipeline], pd.DataFrame, dict[str, tuple[np.ndarray, np.ndarray]]]:
    fitted = {}
    metric_rows = []
    outputs = {}
    w = compute_sample_weight(class_weight="balanced", y=y_train)
    for name, pipe in models.items():
        p = clone(pipe)
        p.fit(X_train, y_train, model__sample_weight=w)
        probs = p.predict_proba(X_test)[:, 1]
        preds = (probs >= threshold).astype(int)
        fitted[name] = p
        outputs[name] = (preds, probs)
        metric_rows.append({"model": name, **classification_metrics(y_test, preds, probs)})
    return fitted, pd.DataFrame(metric_rows), outputs


# ---------------------------------------------------------------------------
# Plots
# ---------------------------------------------------------------------------
def save_fig(fig: plt.Figure, out_dir: Path, stem: str) -> None:
    fig.savefig(out_dir / f"{stem}.png", dpi=200, bbox_inches="tight")
    plt.close(fig)


def plot_model_comparison(cv: pd.DataFrame, ext: pd.DataFrame, out_dir: Path) -> None:
    merged = cv[["model", "balanced_accuracy_mean"]].merge(
        ext[["model", "balanced_accuracy"]], on="model"
    ).sort_values("balanced_accuracy_mean")
    y = np.arange(len(merged))
    fig, ax = plt.subplots(figsize=(9, 5))
    ax.barh(y - 0.18, merged["balanced_accuracy_mean"], height=0.34,
            label="Train 5-fold CV", color="#4C78A8")
    ax.barh(y + 0.18, merged["balanced_accuracy"], height=0.34,
            label="Test set", color="#E45756")
    ax.set_yticks(y, merged["model"])
    ax.set_xlim(0, 1)
    ax.set_xlabel("Balanced accuracy")
    ax.set_title("Feature Model Comparison")
    ax.legend(frameon=False)
    ax.grid(axis="x", alpha=0.25)
    save_fig(fig, out_dir, "model_comparison")


def plot_roc_pr(y_true: np.ndarray, outputs: dict, out_dir: Path) -> None:
    fig, axes = plt.subplots(1, 2, figsize=(12, 5))
    for name, (_, probs) in outputs.items():
        fpr, tpr, _ = roc_curve(y_true, probs)
        prec, rec, _ = precision_recall_curve(y_true, probs)
        axes[0].plot(fpr, tpr, label=f"{name} ({roc_auc_score(y_true, probs):.3f})")
        axes[1].plot(rec, prec, label=f"{name} ({average_precision_score(y_true, probs):.3f})")
    axes[0].plot([0, 1], [0, 1], "--", color="#888", linewidth=0.8)
    axes[0].set(xlabel="FPR", ylabel="TPR", title="Test ROC curves")
    axes[1].set(xlabel="Recall", ylabel="Precision", title="Test PR curves")
    for ax in axes:
        ax.legend(fontsize=8, frameon=False)
        ax.grid(alpha=0.25)
    fig.tight_layout()
    save_fig(fig, out_dir, "roc_pr_curves")


def plot_confusion(y_true: np.ndarray, preds: np.ndarray, model_name: str, out_dir: Path) -> None:
    m = confusion_matrix(y_true, preds, labels=[0, 1])
    pct = m / m.sum(axis=1, keepdims=True) * 100  # row-wise percentage
    fig, ax = plt.subplots(figsize=(5.5, 5))
    im = ax.imshow(pct, cmap="Blues", vmin=0, vmax=100)
    for r in range(2):
        for c in range(2):
            label = f"{pct[r, c]:.1f}%\n(n={m[r, c]})"
            ax.text(c, r, label, ha="center", va="center", fontsize=14,
                    color="white" if pct[r, c] > 50 else "black")
    ax.set_xticks([0, 1], ["Benign", "Malware"])
    ax.set_yticks([0, 1], ["Benign", "Malware"])
    ax.set_xlabel("Predicted"); ax.set_ylabel("Ground truth")
    ax.set_title(f"Confusion matrix: {model_name}")
    fig.colorbar(im, ax=ax, shrink=0.8, label="% of ground-truth class")
    save_fig(fig, out_dir, "confusion_matrix")


def plot_score_distribution(y_true: np.ndarray, probs: np.ndarray, model_name: str, out_dir: Path,
                           threshold: float = 0.5) -> None:
    """Predicted probability histograms split by confusion-matrix quadrant (TP/TN/FP/FN)."""
    preds = (probs >= threshold).astype(int)
    tn_mask = (y_true == 0) & (preds == 0)
    fp_mask = (y_true == 0) & (preds == 1)
    fn_mask = (y_true == 1) & (preds == 0)
    tp_mask = (y_true == 1) & (preds == 1)
    quadrants = [
        ("TN (benign → benign)", probs[tn_mask], "#4C78A8"),
        ("FP (benign → malware) ✗", probs[fp_mask], "#F58518"),
        ("FN (malware → benign) ✗", probs[fn_mask], "#72B06B"),
        ("TP (malware → malware)", probs[tp_mask], "#E45756"),
    ]
    fig, axes = plt.subplots(2, 2, figsize=(10, 8))
    bins = np.linspace(0, 1, 41)
    for ax, (label, scores, color) in zip(axes.flat, quadrants):
        ax.hist(scores, bins=bins, color=color, edgecolor="white", linewidth=0.3, alpha=0.85)
        ax.axvline(threshold, color="black", linestyle="--", linewidth=0.8, alpha=0.4)
        ax.set_title(f"{label}  (n={len(scores)})")
        ax.set_xlim(0, 1)
        ax.set_xlabel("Predicted probability (malware)")
        ax.set_ylabel("Count")
    fig.suptitle(f"Score distribution by quadrant: {model_name}", fontsize=13, y=1.01)
    fig.tight_layout()
    save_fig(fig, out_dir, "score_distribution")


def plot_importance(importance_df: pd.DataFrame, model_name: str, out_dir: Path) -> None:
    frame = importance_df.sort_values("importance_mean")
    fig, ax = plt.subplots(figsize=(9, 5.5))
    ax.barh(frame["feature"], frame["importance_mean"], xerr=frame["importance_std"],
            color="#4C78A8", alpha=0.9)
    ax.set_xlabel("Decrease in balanced accuracy after permutation")
    ax.set_title(f"Permutation Importance: {model_name}")
    ax.grid(axis="x", alpha=0.25)
    save_fig(fig, out_dir, "feature_importance")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--csv", type=Path, default=Path("dataset.csv"))
    parser.add_argument("--output-dir", type=Path, default=Path("pe_model_output"))
    parser.add_argument("--train-ratio", type=float, default=0.6)
    parser.add_argument("--threshold", type=float, default=0.3)
    parser.add_argument(
        "--exclude-debug-directory",
        action="store_true",
        help=(
            "exclude debug_directory_present and clear the debug bit from "
            "directory_presence_pattern"
        ),
    )
    return parser.parse_args()


def main() -> int:
    global NUMERIC_FEATURES, MODEL_FEATURES

    args = parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    if args.exclude_debug_directory:
        NUMERIC_FEATURES = [
            feature for feature in NUMERIC_FEATURES
            if feature != "debug_directory_present"
        ]
        MODEL_FEATURES = NUMERIC_FEATURES + CATEGORICAL_FEATURES
        print(
            "Ablation: excluding debug_directory_present and clearing the "
            "debug bit in directory_presence_pattern",
            flush=True,
        )

    print("[1/5] Loading data...", flush=True)
    rows = load_dataset(args.csv)

    # 60/40 random per-label split
    from collections import defaultdict
    random.seed(42)
    groups: dict[str, list] = defaultdict(list)
    for r in rows:
        groups[r["label"]].append(r)
    train_rows, test_rows = [], []
    for label, grp in groups.items():
        random.shuffle(grp)
        cutoff = int(len(grp) * args.train_ratio)
        train_rows.extend(grp[:cutoff])
        test_rows.extend(grp[cutoff:])
    print(f"  Train: {len(train_rows)} ({sum(1 for r in train_rows if r['label']=='0')} benign, "
          f"{sum(1 for r in train_rows if r['label']=='1')} malware)")
    print(f"  Test:  {len(test_rows)} ({sum(1 for r in test_rows if r['label']=='0')} benign, "
          f"{sum(1 for r in test_rows if r['label']=='1')} malware)")

    print("[2/5] Extracting PE features...", flush=True)
    def extract_split(split_rows, label_text):
        features, failures = [], []
        for i, r in enumerate(split_rows, 1):
            sha = r["sha256"].lower()
            try:
                data = Path(r["path"]).read_bytes()
                actual = sha256_bytes(data)
                if actual != sha:
                    raise ValueError(f"hash mismatch: {sha} vs {actual}")
                feats = extract_features(Path(r["path"]))
                features.append({"sha256": sha, "source": r.get("source", ""),
                                 "label": int(r["label"]), **feats})
                ok = "ok"
            except Exception as e:
                failures.append({"sha256": sha, "path": r.get("path", ""),
                                 "reason": f"{type(e).__name__}: {e}"})
                ok = "FAIL"
            if i % 200 == 0 or i == 1 or i == len(split_rows):
                print(f"  [{label_text}] {i}/{len(split_rows)}: {ok}")
        return pd.DataFrame(features), failures

    train_frame, train_fail = extract_split(train_rows, "train")
    test_frame, test_fail = extract_split(test_rows, "test")
    all_fail = train_fail + test_fail
    print(f"  Extracted: train={len(train_frame)}, test={len(test_frame)}, failures={len(all_fail)}")

    if args.exclude_debug_directory:
        # directory_presence_pattern bit1 also encodes Debug Directory presence.
        # Clear it so the ablated model cannot recover the removed signal.
        for frame in (train_frame, test_frame):
            frame["directory_presence_pattern"] = (
                frame["directory_presence_pattern"].astype(int) & ~0b10
            )

    X_train = train_frame[MODEL_FEATURES]
    y_train = train_frame["label"].to_numpy(dtype=int)
    X_test = test_frame[MODEL_FEATURES]
    y_test = test_frame["label"].to_numpy(dtype=int)

    print("[3/5] 5-fold cross-validation on training set...", flush=True)
    models = build_models()
    cv_results = cross_validate(models, X_train, y_train, threshold=args.threshold)
    primary = cv_results.sort_values(["balanced_accuracy_mean", "f1_mean"], ascending=False).iloc[0]["model"]
    print(f"  Primary model by CV balanced accuracy: {primary}")

    print("[4/5] Evaluating on test set...", flush=True)
    fitted, ext_metrics, outputs = evaluate_external(models, X_train, y_train, X_test, y_test, threshold=args.threshold)
    print(ext_metrics[["model", "balanced_accuracy", "f1", "roc_auc"]].to_string(index=False))

    print("[5/6] Computing permutation importance on primary model...", flush=True)
    imp_result = permutation_importance(
        fitted[primary], X_train, y_train,
        scoring="balanced_accuracy", n_repeats=30, random_state=SEED, n_jobs=1,
    )
    importance = pd.DataFrame({
        "feature": MODEL_FEATURES,
        "importance_mean": imp_result.importances_mean,
        "importance_std": imp_result.importances_std,
    }).sort_values("importance_mean", ascending=False)
    print(importance.to_string(index=False))

    print("[6/6] Saving outputs...", flush=True)
    train_frame.to_csv(args.output_dir / "train_features.csv", index=False, encoding="utf-8-sig")
    test_frame.to_csv(args.output_dir / "test_features.csv", index=False, encoding="utf-8-sig")
    cv_results.to_csv(args.output_dir / "cv_results.csv", index=False, encoding="utf-8-sig")
    ext_metrics.to_csv(args.output_dir / "test_metrics.csv", index=False, encoding="utf-8-sig")

    if all_fail:
        pd.DataFrame(all_fail).to_csv(args.output_dir / "failures.csv", index=False, encoding="utf-8-sig")

    # Predictions with audit
    pred_out = test_frame[["sha256", "source", "label"] + MODEL_FEATURES +
                          [c for c in test_frame.columns if c.startswith("audit_")]].copy()
    for name, (preds, probs) in outputs.items():
        pred_out[f"{name}_pred"] = preds
        pred_out[f"{name}_prob"] = probs
    pred_out.to_csv(args.output_dir / "predictions.csv", index=False, encoding="utf-8-sig")

    importance.to_csv(args.output_dir / "feature_importance.csv", index=False, encoding="utf-8-sig")
    joblib.dump(fitted[primary], args.output_dir / "model.joblib")
    print(f"  Exported model: {args.output_dir / 'model.joblib'}")
    plot_model_comparison(cv_results, ext_metrics, args.output_dir)
    plot_roc_pr(y_test, outputs, args.output_dir)
    plot_confusion(y_test, outputs[primary][0], primary, args.output_dir)
    plot_score_distribution(y_test, outputs[primary][1], primary, args.output_dir, threshold=args.threshold)
    plot_importance(importance, primary, args.output_dir)

    print(f"\nDone — all output in {args.output_dir}/")
    print(f"  Primary model: {primary}")
    print(f"  Test balanced accuracy: {ext_metrics.set_index('model').loc[primary, 'balanced_accuracy']:.4f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
