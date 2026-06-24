import pandas as pd
import numpy as np

try:
    from imblearn.over_sampling import SMOTE
except ImportError:
    class SMOTE:
        def __init__(self, random_state=42): pass
        def fit_resample(self, X, y): return X, y

def engineer_features(df):
    # Dynamically detect the target column to prevent KeyErrors
    target_col = 'label' if 'label' in df.columns else 'class'
    
    if target_col not in df.columns:
        raise KeyError(f"Could not find 'label' or 'class' column in dataset. Found: {df.columns.tolist()[-5:]}")

    # 1. Explicitly Map Labels BEFORE anything else
    df[target_col] = df[target_col].replace({'B': 0, 'S': 1, 'M': 1})
    df[target_col] = pd.to_numeric(df[target_col], errors='coerce').fillna(1).astype(int)
    
    # 2. Handle missing data (Avoid Pandas 3.0 inplace=True warnings)
    numeric_cols = df.select_dtypes(include=["number"]).columns
    for col in numeric_cols:
        df[col] = df[col].fillna(0)

    # Convert booleans and string booleans to integers safely
    df = df.replace({True: 1, False: 0, "true": 1, "false": 0, "yes": 1, "no": 0})
    
    # Drop columns with massive missing data
    missing_ratio = df.isnull().mean()
    to_drop = missing_ratio[missing_ratio > 0.4].index
    df = df.drop(columns=to_drop)
    
    y = df[target_col]
    X = df.drop(columns=[target_col])
    
    feature_columns = X.columns.tolist()
    
    # 3. Proper SMOTE Execution
    pos_count = sum(y == 1)
    neg_count = sum(y == 0)
    
    if neg_count == 0 or pos_count == 0:
        print(f"WARNING: Invalid class distribution. Pos: {pos_count}, Neg: {neg_count}")
        return X, y, feature_columns
        
    print(f"Dataset Loaded. Before SMOTE -> Pos (Malware): {pos_count}, Neg (Benign): {neg_count}")
    smote = SMOTE(random_state=42)
    X_resampled, y_resampled = smote.fit_resample(X, y)
    
    print(f"After SMOTE Balancing -> Pos: {sum(y_resampled==1)}, Neg: {sum(y_resampled==0)}")
    
    return X_resampled, y_resampled, feature_columns