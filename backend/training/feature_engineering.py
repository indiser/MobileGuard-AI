import pandas as pd
import numpy as np

# We stub SMOTE and StandardScaler if they aren't installed yet locally.
try:
    from sklearn.preprocessing import StandardScaler
    from imblearn.over_sampling import SMOTE
except ImportError:
    class StandardScaler:
        def fit_transform(self, X): return X
    class SMOTE:
        def __init__(self, random_state=42): pass
        def fit_resample(self, X, y): return X, y

def engineer_features(df, target_col='label'):
    # numeric_only=True avoids the pandas FutureWarning / TypeError on mixed-type DataFrames
    df.fillna(df.median(numeric_only=True), inplace=True)
    
    missing_ratio = df.isnull().mean()
    to_drop = missing_ratio[missing_ratio > 0.4].index
    df.drop(columns=to_drop, inplace=True)
    
    y = df[target_col]
    X = df.drop(columns=[target_col])
    
    feature_columns = X.columns.tolist()
    
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    
    pos_count = sum(y == 1)
    neg_count = sum(y == 0)
    
    if neg_count == 0 or pos_count == 0:
        return X_scaled, y, feature_columns, scaler

    ratio = max(pos_count, neg_count) / min(pos_count, neg_count)
    if ratio > 5.0:
        smote = SMOTE(random_state=42)
        X_res, y_res = smote.fit_resample(X_scaled, y)
    else:
        X_res, y_res = X_scaled, y
        
    return X_res, y_res, feature_columns, scaler
