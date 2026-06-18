import pandas as pd
import numpy as np
import os
import json
import joblib

try:
    import xgboost as xgb
    from sklearn.model_selection import train_test_split
except ImportError:
    xgb = None
    train_test_split = None

# Support running as a module (python -m backend.training.train_xgboost)
# or as a direct script (python train_xgboost.py) from any directory.
try:
    from backend.training.feature_engineering import engineer_features
    from backend.training.evaluate import evaluate_model
except ImportError:
    from feature_engineering import engineer_features  # type: ignore
    from evaluate import evaluate_model  # type: ignore

# Resolve the models/ directory relative to this file regardless of CWD.
# backend/training/train_xgboost.py  →  go up two levels  →  project root/models/
_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
MODELS_DIR = os.path.normpath(os.path.join(_THIS_DIR, "..", "..", "models"))


def _make_synthetic_dataset(n_benign: int = 800, n_malicious: int = 800, seed: int = 42) -> pd.DataFrame:
    """
    Generate a labelled synthetic dataset whose feature distributions match
    what StaticAnalyzer / DynamicAnalyzer / RiskScorer actually produce.

    Feature columns (37 total) mirror the feature_vector built in RiskScorer.score():
      0  permission_danger_score   (0-100)
      1  dangerous_permission_count
      2  suspicious_api_count
      3  api_suspicion_score       (0-100)
      4  high_entropy_count
      5  obfuscation_score         (0-100)
      6  c2_hit_count
      7  is_self_signed            (0/1)
      8  cert_trust_score          (0-100)
      9  has_native_code           (0/1)
      10 native_risk_score         (0-100)
      11 graph_density             (0-1)
      12 graph_node_count
      13 graph_edge_count
      14-36  (padding zeros — reserved for future features)
    """
    rng = np.random.default_rng(seed)

    def _clip(arr, lo, hi):
        return np.clip(arr, lo, hi)

    # ── Benign samples ──────────────────────────────────────────────────────
    b = n_benign
    benign = {
        "permission_danger_score":    _clip(rng.normal(15,  10, b), 0, 100),
        "dangerous_permission_count": _clip(rng.poisson(1.5, b),    0,  22).astype(float),
        "suspicious_api_count":       _clip(rng.poisson(2,   b),    0,  50).astype(float),
        "api_suspicion_score":        _clip(rng.normal(16,   8, b), 0, 100),
        "high_entropy_count":         _clip(rng.poisson(10,  b),    0, 500).astype(float),
        "obfuscation_score":          _clip(rng.normal(12,   8, b), 0, 100),
        "c2_hit_count":               np.zeros(b),
        "is_self_signed":             rng.choice([0, 1], size=b, p=[0.4, 0.6]).astype(float),
        "cert_trust_score":           _clip(rng.normal(70,  15, b), 0, 100),
        "has_native_code":            rng.choice([0, 1], size=b, p=[0.6, 0.4]).astype(float),
        "native_risk_score":          _clip(rng.normal(10,  10, b), 0, 100),
        "graph_density":              _clip(rng.normal(0.02, 0.01, b), 0, 1),
        "graph_node_count":           _clip(rng.normal(800, 400, b), 0, 10000).astype(float),
        "graph_edge_count":           _clip(rng.normal(900, 500, b), 0, 30000).astype(float),
    }

    # ── Malicious samples ───────────────────────────────────────────────────
    m = n_malicious
    malicious = {
        "permission_danger_score":    _clip(rng.normal(70,  18, m), 0, 100),
        "dangerous_permission_count": _clip(rng.poisson(6,   m),    0,  22).astype(float),
        "suspicious_api_count":       _clip(rng.poisson(18,  m),    0,  50).astype(float),
        "api_suspicion_score":        _clip(rng.normal(72,  18, m), 0, 100),
        "high_entropy_count":         _clip(rng.poisson(80,  m),    0, 500).astype(float),
        "obfuscation_score":          _clip(rng.normal(65,  20, m), 0, 100),
        "c2_hit_count":               _clip(rng.poisson(1.2, m),    0,  20).astype(float),
        "is_self_signed":             rng.choice([0, 1], size=m, p=[0.1, 0.9]).astype(float),
        "cert_trust_score":           _clip(rng.normal(35,  20, m), 0, 100),
        "has_native_code":            rng.choice([0, 1], size=m, p=[0.3, 0.7]).astype(float),
        "native_risk_score":          _clip(rng.normal(45,  25, m), 0, 100),
        "graph_density":              _clip(rng.normal(0.05, 0.03, m), 0, 1),
        "graph_node_count":           _clip(rng.normal(600, 300, m), 0, 10000).astype(float),
        "graph_edge_count":           _clip(rng.normal(700, 400, m), 0, 30000).astype(float),
    }

    feature_cols = list(benign.keys())  # 14 real features

    df_benign   = pd.DataFrame(benign)
    df_malicious = pd.DataFrame(malicious)

    # Padding columns feature_14 … feature_36 (reserved, all zero for now)
    for i in range(14, 37):
        df_benign[f"feature_{i}"]   = 0.0
        df_malicious[f"feature_{i}"] = 0.0

    df_benign["label"]    = 0
    df_malicious["label"] = 1

    df = pd.concat([df_benign, df_malicious], ignore_index=True)
    df = df.sample(frac=1, random_state=seed).reset_index(drop=True)
    return df


def train():
    if xgb is None or train_test_split is None:
        print("ERROR: xgboost or scikit-learn not installed. Run: pip install xgboost scikit-learn")
        return

    print("Generating synthetic training data...")
    # Swap the comment below to use real Drebin/CIC-AndMal data once available:
    # df = pd.read_parquet(os.path.join(MODELS_DIR, "..", "data", "drebin_features.parquet"))
    df = _make_synthetic_dataset(n_benign=800, n_malicious=800)
    print(f"  {len(df)} samples | {df['label'].sum()} malicious / {(df['label']==0).sum()} benign")

    print("Engineering features...")
    X, y, feature_columns, scaler = engineer_features(df)

    print("Splitting dataset...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.15, stratify=y, random_state=42
    )
    X_train, X_val, y_train, y_val = train_test_split(
        X_train, y_train, test_size=0.15 / 0.85, stratify=y_train, random_state=42
    )

    pos_count = int((y_train == 1).sum())
    neg_count = int((y_train == 0).sum())
    scale_pos_weight = neg_count / pos_count if pos_count > 0 else 1.0
    print(f"  Train: {len(y_train)} | Val: {len(y_val)} | Test: {len(y_test)}")
    print(f"  scale_pos_weight: {scale_pos_weight:.2f}")

    print("Training XGBoost...")
    model = xgb.XGBClassifier(
        n_estimators=300,
        max_depth=6,
        learning_rate=0.05,
        subsample=0.8,
        colsample_bytree=0.8,
        scale_pos_weight=scale_pos_weight,
        eval_metric=["logloss", "auc"],
        early_stopping_rounds=20,
        random_state=42,
        tree_method="hist",   # faster on CPU
    )

    model.fit(
        X_train, y_train,
        eval_set=[(X_val, y_val)],
        verbose=50,
    )

    print("Evaluating model...")
    evaluate_model(model, X_test, y_test, feature_columns)

    print("Saving model and artifacts...")
    os.makedirs(MODELS_DIR, exist_ok=True)

    model_path = os.path.join(MODELS_DIR, "xgboost_mobileguard.json")
    model.save_model(model_path)
    print(f"  Model saved  → {model_path}")

    cols_path = os.path.join(MODELS_DIR, "feature_columns.json")
    with open(cols_path, "w") as f:
        json.dump(feature_columns, f)
    print(f"  Columns saved → {cols_path}")

    scaler_path = os.path.join(MODELS_DIR, "scaler.pkl")
    joblib.dump(scaler, scaler_path)
    print(f"  Scaler saved  → {scaler_path}")

    print("Training complete.")


if __name__ == "__main__":
    train()
