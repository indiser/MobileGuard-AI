from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix,
    roc_curve
)
import numpy as np

def calculate_metrics(y_true, y_pred, y_prob):
    """
    Calculates advanced SOC-grade metrics, including optimal thresholds 
    and specific False Discovery Rates.
    """
    
    # Handle edge case where dataset is 100% benign or 100% malware
    if len(set(y_true)) < 2:
        return {
            "error": "Dataset must contain both benign (0) and malware (1) samples to calculate AUC/ROC.",
            "total_samples": len(y_true)
        }

    accuracy = accuracy_score(y_true, y_pred)
    precision = precision_score(y_true, y_pred, zero_division=0)
    recall = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)

    try:
        auc = roc_auc_score(y_true, y_prob)
    except Exception:
        auc = 0.0

    tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()
    
    # SOC Specific Rates
    # False Positive Rate (How many clean apps did we block?)
    fpr = fp / max(fp + tn, 1)
    
    # False Negative Rate (How much malware slipped through?)
    fnr = fn / max(fn + tp, 1)
    
    # False Discovery Rate (When we flag an app as malware, how often are we wrong?)
    fdr = fp / max(fp + tp, 1)

    # ---------------------------------------------------------
    # Calculate Optimal Threshold (Youden's J statistic)
    # This tells us if a threshold of 50 is actually correct for the ML model.
    # ---------------------------------------------------------
    try:
        fpr_curve, tpr_curve, thresholds = roc_curve(y_true, y_prob)
        # J = Sensitivity + Specificity - 1 = TPR - FPR
        j_scores = tpr_curve - fpr_curve
        optimal_idx = np.argmax(j_scores)
        optimal_threshold = thresholds[optimal_idx]
    except Exception:
        optimal_threshold = 0.5

    return {
        "overall_accuracy": round(accuracy, 4),
        "f1_score": round(f1, 4),
        "precision_confidence": round(precision, 4),
        "recall_detection_rate": round(recall, 4),
        "roc_auc_score": round(auc, 4),
        "optimal_ml_threshold": round(optimal_threshold, 4),
        
        # Raw Counts
        "true_positives_blocked_malware": int(tp),
        "true_negatives_allowed_benign": int(tn),
        "false_positives_wrongly_blocked": int(fp),
        "false_negatives_missed_malware": int(fn),
        
        # SOC Rates
        "false_positive_rate": round(fpr, 4),
        "false_negative_rate": round(fnr, 4),
        "false_discovery_rate": round(fdr, 4),
        
        "total_analyzed": len(y_true)
    }