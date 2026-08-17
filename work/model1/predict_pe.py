from pathlib import Path
import sys

import joblib
import pandas as pd

from pe_feature_model import extract_features, MODEL_FEATURES

THRESHOLD = 0.3

model = joblib.load("model.joblib")
sample = Path(sys.argv[1])

# 静态提取特征，不执行样本
features = extract_features(sample)
X = pd.DataFrame(
    [{name: features[name] for name in MODEL_FEATURES}],
    columns=MODEL_FEATURES,
)

probability = float(model.predict_proba(X)[0, 1])
prediction = int(probability >= THRESHOLD)

print(f"malware_probability: {probability:.6f}")
print(f"prediction: {prediction}")  # 1=malware，0=benign