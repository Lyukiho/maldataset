"""Model call example for the model1-1 no_debug package.

Usage:
    python predict_pe.py <path-to-pe-file>

The script only performs static feature extraction; it never executes the
target PE file.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

# Keep joblib/sklearn loading quiet and deterministic for this single-file
# inference example.
os.environ.setdefault("LOKY_MAX_CPU_COUNT", "1")
os.environ.setdefault("OMP_NUM_THREADS", "1")

import joblib
import pandas as pd

from pe_feature_model import (
    CATEGORICAL_FEATURES,
    NUMERIC_FEATURES,
    extract_features,
)


THRESHOLD = 0.3
MODEL_PATH = Path(__file__).resolve().parent / "model.joblib"

# model1-1 was trained with --exclude-debug-directory (no_debug), so the
# prediction input must use the same ablated feature set.
NO_DEBUG_NUMERIC_FEATURES = [
    name for name in NUMERIC_FEATURES if name != "debug_directory_present"
]
MODEL_FEATURES = NO_DEBUG_NUMERIC_FEATURES + CATEGORICAL_FEATURES


def predict_one(path: Path) -> dict[str, float | int | str]:
    if not path.is_file():
        raise FileNotFoundError(f"PE file not found: {path}")

    model = joblib.load(MODEL_PATH)
    features = extract_features(path)

    # Match no_debug preprocessing: clear the Debug Directory bit encoded in
    # directory_presence_pattern.
    features["directory_presence_pattern"] = (
        int(features["directory_presence_pattern"]) & ~0b10
    )

    X = pd.DataFrame(
        [{name: features[name] for name in MODEL_FEATURES}],
        columns=MODEL_FEATURES,
    )
    probability = float(model.predict_proba(X)[0, 1])
    prediction = int(probability >= THRESHOLD)

    return {
        "path": str(path),
        "malware_probability": probability,
        "prediction": prediction,
        "prediction_label": "malware" if prediction == 1 else "benign",
    }


def main() -> int:
    if len(sys.argv) != 2:
        print("Usage: python predict_pe.py <path-to-pe-file>")
        return 2

    sample = Path(sys.argv[1]).resolve()
    try:
        result = predict_one(sample)
    except Exception as exc:
        print(f"Prediction failed: {type(exc).__name__}: {exc}")
        return 1

    print(f"file: {result['path']}")
    print(f"malware_probability: {result['malware_probability']:.6f}")
    print(f"prediction: {result['prediction']} ({result['prediction_label']})")
    print(f"threshold: {THRESHOLD}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
