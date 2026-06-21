try:
    import matplotlib.pyplot as plt
    from sklearn.metrics import classification_report, roc_auc_score, confusion_matrix
    import shap
except ImportError:
    pass

import os

# Resolve models/ dir relative to this file so the SHAP plot saves correctly
# regardless of the working directory.
_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_MODELS_DIR = os.path.normpath(os.path.join(_THIS_DIR, "..", "models"))

def evaluate_model(model, X_test, y_test, feature_columns):
    try:
        y_pred_proba = model.predict_proba(X_test)[:, 1]
        y_pred = (y_pred_proba > 0.5).astype(int)
        
        print("=== Classification Report ===")
        print(classification_report(y_test, y_pred))
        
        auc = roc_auc_score(y_test, y_pred_proba)
        print(f"ROC-AUC Score: {auc:.4f}")
        
        cm = confusion_matrix(y_test, y_pred)
        print("=== Confusion Matrix ===")
        print(cm)
        
        tn, fp, fn, tp = cm.ravel()
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
        fnr = fn / (fn + tp) if (fn + tp) > 0 else 0
        
        print(f"FPR at threshold 0.5: {fpr:.4f}")
        print(f"FNR at threshold 0.5: {fnr:.4f}")
        
        print("\nTARGET THRESHOLDS CHECK:")
        f1 = 2 * tp / (2 * tp + fp + fn) if (2 * tp + fp + fn) > 0 else 0
        print(f"F1: {f1:.4f} (> 0.90 required: {f1 > 0.90})")
        print(f"FPR: {fpr:.4f} (< 0.05 required: {fpr < 0.05})")
        print(f"FNR: {fnr:.4f} (< 0.05 required: {fnr < 0.05})")
        print(f"AUC: {auc:.4f} (> 0.97 required: {auc > 0.97})")
        
        try:
            explainer = shap.TreeExplainer(model)
            shap_values = explainer.shap_values(X_test)
            os.makedirs(_MODELS_DIR, exist_ok=True)
            shap_plot_path = os.path.join(_MODELS_DIR, "shap_feature_importance.png")
            shap.summary_plot(shap_values, X_test, feature_names=feature_columns, show=False)
            plt.savefig(shap_plot_path, bbox_inches='tight')
            plt.close()
            print(f"SHAP plot saved to {shap_plot_path}")
        except Exception as e:
            print(f"Failed to generate SHAP plot: {e}")
    except Exception as e:
        print(f"Evaluation missing dependencies: {e}")
