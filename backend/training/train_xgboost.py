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

from sklearn.metrics import (
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix,
    accuracy_score
)

# Support running as a module (python -m backend.training.train_xgboost)
# or as a direct script (python train_xgboost.py) from any directory.
try:
    from backend.training.feature_engineering import engineer_features
    from backend.training.evaluate import evaluate_model
except ImportError:
    from feature_engineering import engineer_features  # type: ignore
    from evaluate import evaluate_model  # type: ignore


_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
MODELS_DIR = os.path.normpath(os.path.join(_THIS_DIR, "..", "models"))
PROJECT_ROOT = os.path.normpath(os.path.join(_THIS_DIR, "..", ".."))
DATASET_PATH = os.path.join(PROJECT_ROOT, "dataset", "malware_dataset.csv")

def train():
    if xgb is None or train_test_split is None:
        print("ERROR: xgboost or scikit-learn not installed. Run: pip install xgboost scikit-learn")
        return

    # Swap the comment below to use real Drebin/CIC-AndMal data once available:
    if not os.path.exists(DATASET_PATH):
        print(f"FATAL ERROR: Could not find dataset at {DATASET_PATH}")
        print("Please create the 'dataset' folder in your project root and place 'malware_dataset.csv' inside it.")
        return

    df = pd.read_csv(DATASET_PATH, low_memory=False)

    df["label"] = df["class"].map({
        "B": 0,
        "S": 1
    })
    df.drop(columns=["class"], inplace=True)

    print(f"  {len(df)} samples | {df['label'].sum()} malicious / {(df['label']==0).sum()} benign")


    non_numeric = df.select_dtypes(
        exclude=["number"]
    ).columns.tolist()

    non_numeric = [
        c for c in non_numeric
        if c != "label"
    ]

    if non_numeric:
        print("Dropping:", non_numeric)
        df.drop(columns=non_numeric, inplace=True)
    
    print("Engineering features...")
    X, y, feature_columns = engineer_features(df)

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
        max_depth=5,
        learning_rate=0.05,
        subsample=0.8,
        colsample_bytree=0.8,
        scale_pos_weight=scale_pos_weight,
        eval_metric=["logloss", "auc"],
        early_stopping_rounds=20,
        random_state=42,
        min_child_weight=3,
        gamma=0.1,
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

    y_pred = model.predict(X_test)
    y_prob = model.predict_proba(X_test)[:,1]

    cm = confusion_matrix(y_test, y_pred)
    tn, fp, fn, tp = cm.ravel()

    metrics = {
        "accuracy": float(accuracy_score(y_test, y_pred)),
        "auc": float(roc_auc_score(y_test, y_prob)),
        "precision": float(precision_score(y_test, y_pred)),
        "recall": float(recall_score(y_test, y_pred)),
        "f1": float(f1_score(y_test, y_pred)),
        "true_positives": int(tp),
        "true_negatives": int(tn),
        "false_positives": int(fp),
        "false_negatives": int(fn),
        "false_positive_rate": float(fp / max(fp + tn, 1)),
        "false_negative_rate": float(fn / max(fn + tp, 1))
    }

    with open(os.path.join(MODELS_DIR,"model_metrics.json"),"w") as f:
        json.dump(metrics,f,indent=4)

    importance = pd.DataFrame({
        "feature": feature_columns,
        "importance": model.feature_importances_
    })

    importance = importance.sort_values(
        "importance",
        ascending=False
    )

    print("\nTop 25 Features")
    print(importance.head(25))

    model_path = os.path.join(MODELS_DIR, "xgboost_mobileguard.json")
    model.save_model(model_path)
    print(f"  Model saved  → {model_path}")

    cols_path = os.path.join(MODELS_DIR, "feature_columns.json")
    with open(cols_path, "w") as f:
        json.dump(feature_columns, f, indent=4)
    print(f"  Columns saved → {cols_path}")

    print("Training complete.")


if __name__ == "__main__":
    train()
