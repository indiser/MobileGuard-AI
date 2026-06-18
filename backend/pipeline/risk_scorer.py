import os
import xgboost as xgb
import shap
import numpy as np
from dataclasses import dataclass
from typing import List, Dict, Tuple

try:
    from backend.pipeline.static_analyzer import StaticFeatures
    from backend.pipeline.dynamic_analyzer import DynamicFeatures
    from backend.pipeline.llm_analyzer import LLMFeatures
except ImportError:
    pass

@dataclass
class RiskScore:
    composite_score: float
    action: str
    dimension_scores: Dict[str, float]
    ml_score: float
    shap_top_features: List[Tuple[str, float]]
    shap_explanation: str
    boost_rules_applied: List[str]

class RiskScorer:
    def __init__(self, model_path: str = "models/xgboost_mobileguard.json"):
        self.model_path = model_path
        self.xgb_model = None
        self.explainer = None
        
        if os.path.exists(model_path):
            try:
                self.xgb_model = xgb.XGBClassifier()
                self.xgb_model.load_model(model_path)
                self.explainer = shap.TreeExplainer(self.xgb_model)
            except Exception as e:
                print(f"Warning: Failed to load XGBoost model: {e}")
                self.xgb_model = None
        else:
            print("Warning: No trained model found. Using heuristic scoring.")

    def get_action(self, score: float) -> str:
        if score <= 25:  return "APPROVE"
        if score <= 50:  return "MONITOR"
        if score <= 75:  return "ESCALATE"
        return "BLOCK"

    def score(self, static: 'StaticFeatures', dynamic: 'DynamicFeatures', llm: 'LLMFeatures') -> RiskScore:
        feature_vector = np.array([[
            static.permission_danger_score,
            static.dangerous_permission_count,
            static.suspicious_api_count,
            static.api_suspicion_score,
            static.high_entropy_count,
            static.obfuscation_score,
            static.c2_hit_count,
            1 if static.is_self_signed else 0,
            static.cert_trust_score,
            1 if static.has_native_code else 0,
            static.native_risk_score,
            static.graph_density,
            static.graph_node_count,
            static.graph_edge_count
        ]])
        
        if feature_vector.shape[1] < 37:
            padding = np.zeros((1, 37 - feature_vector.shape[1]))
            feature_vector = np.hstack((feature_vector, padding))

        ml_score = 0.0
        shap_top_features = []
        shap_explanation = "Heuristic scoring applied (no ML model)."

        if self.xgb_model:
            try:
                probs = self.xgb_model.predict_proba(feature_vector)
                ml_score = float(probs[0][1] * 100.0)
                
                shap_values = self.explainer.shap_values(feature_vector)
                
                # TreeExplainer on a binary XGBClassifier returns either:
                #   - a 2-D ndarray of shape (n_samples, n_features)  — newer shap versions
                #   - a list of two arrays [neg_class, pos_class]      — older shap versions
                # Normalise to a 1-D array of per-feature SHAP values for the positive class.
                if isinstance(shap_values, list):
                    # list form: index 1 is positive class
                    shap_val_array = np.array(shap_values[1][0])
                else:
                    # ndarray form: shape is (1, n_features)
                    shap_val_array = np.array(shap_values[0])
                
                feature_names = [
                    "permission_danger", "dangerous_perm_count", "suspicious_api_count",
                    "api_suspicion_score", "high_entropy_count", "obfuscation_score",
                    "c2_hit_count", "is_self_signed", "cert_trust", "has_native",
                    "native_risk", "graph_density", "graph_nodes", "graph_edges"
                ] + [f"feature_{i}" for i in range(14, 37)]
                top_indices = np.argsort(np.abs(shap_val_array))[-5:][::-1]
                
                for idx in top_indices:
                    shap_top_features.append((feature_names[idx], float(shap_val_array[idx])))
                    
                explanation_parts = [f"{name} ({val:+.1f})" for name, val in shap_top_features]
                shap_explanation = "Score driven by: " + ", ".join(explanation_parts)
            except Exception as e:
                print(f"Warning: ML scoring failed: {e}")
                ml_score = static.permission_danger_score * 0.7 + static.api_suspicion_score * 0.3
        else:
            ml_score = static.permission_danger_score * 0.7 + static.api_suspicion_score * 0.3
            shap_top_features = [("permission_danger", static.permission_danger_score), ("api_suspicion", static.api_suspicion_score)]
            
        dimension_scores = {
            "permission_abuse": static.permission_danger_score,
            "obfuscation": static.obfuscation_score,
            "behavioral_anomaly": dynamic.behavioural_anomaly_score,
            "ml_malware": ml_score,
            "developer_trust": 100.0 - static.cert_trust_score,
            "llm_severity": llm.severity_score * 100.0
        }
        
        WEIGHTS = {
            "permission_abuse": 0.20,
            "obfuscation": 0.15,
            "behavioral_anomaly": 0.25,
            "ml_malware": 0.20,
            "developer_trust": 0.10,
            "llm_severity": 0.10,
        }
        
        composite = sum(score * WEIGHTS[dim] for dim, score in dimension_scores.items())
        composite = round(min(100.0, max(0.0, composite)), 1)
        
        boost_rules_applied = []
        
        if dynamic.sms_send_attempts > 0:
            composite = min(100.0, composite + 15)
            boost_rules_applied.append("SMS send attempts detected (+15)")
        if dynamic.c2_domains_hit > 0:
            composite = min(100.0, composite + 20)
            boost_rules_applied.append("C2 domains hit (+20)")
        if dynamic.accessibility_service_abused:
            composite = min(100.0, composite + 12)
            boost_rules_applied.append("Accessibility service abused (+12)")
        if static.c2_hit_count > 0:
            composite = min(100.0, composite + 10)
            boost_rules_applied.append("Static C2 IPs found (+10)")
        if llm.verdict == "CRITICAL":
            composite = min(100.0, composite + 10)
            boost_rules_applied.append("LLM Verdict Critical (+10)")
        if dynamic.silent_install_attempted:
            composite = min(100.0, composite + 15)
            boost_rules_applied.append("Silent install attempted (+15)")
        # NOTE: self-signed cert is already penalised via the developer_trust dimension
        # score (100 - cert_trust_score). Adding a second boost on top would double-count
        # it and unfairly inflate scores for legitimate personal/dev APKs.
            
        action = self.get_action(composite)
        
        return RiskScore(
            composite_score=composite,
            action=action,
            dimension_scores=dimension_scores,
            ml_score=ml_score,
            shap_top_features=shap_top_features,
            shap_explanation=shap_explanation,
            boost_rules_applied=boost_rules_applied
        )
