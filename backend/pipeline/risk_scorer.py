import os
import xgboost as xgb
import shap
import numpy as np
from dataclasses import dataclass
from typing import List, Dict, Tuple
from backend import config
import traceback
import json

try:
    from backend.pipeline.static_analyzer import StaticFeatures
    from backend.pipeline.dynamic_analyzer import DynamicFeatures
    from backend.pipeline.llm_analyzer import LLMFeatures
    from backend.dataset_feature_extractor import extract_from_apk
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
    xgb_probability: float

class RiskScorer:
    def __init__(self, model_path: str = config.MODEL_PATH):
        self.model_path = model_path
        self.xgb_model = None
        self.explainer = None
        print(f"Loading model from: {model_path}")
        print(f"Model exists: {os.path.exists(model_path)}")
        feature_columns_path = config.MODEL_DIR / "feature_columns.json"

        self.feature_columns = []

        try:
            with open(feature_columns_path, "r") as f:
                self.feature_columns = json.load(f)
        except Exception as e:
            print(
                f"Warning: feature columns missing: {e}"
            )
        
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

    def score(self, static: 'StaticFeatures', dynamic: 'DynamicFeatures', llm: 'LLMFeatures', dataset_features=None, yara_result=None) -> RiskScore:
        if dataset_features:
            feature_vector = np.array([
                [
                    dataset_features.get(col, 0)
                    for col in self.feature_columns
                ]
            ])
        else:
            raise ValueError(
                "dataset_features required for ML scoring"
            )
        
        print(
            "Feature count:",
            feature_vector.shape[1]
        )
        ml_score = 0.0
        shap_top_features = []
        shap_explanation = "Heuristic scoring applied (no ML model)."

        if self.xgb_model:
            try:
                print("ML FEATURE VECTOR SHAPE:", feature_vector.shape)
                print("RUNNING XGBOOST")
                probs = self.xgb_model.predict_proba(feature_vector)
                print("XGBOOST PROB:", probs)
                ml_score = float(probs[0][1] * 100.0)

                xgb_probability = float(
                    probs[0][1]
                )
                
                shap_values = self.explainer.shap_values(feature_vector)
                print("XGBOOST MODEL LOADED")
                print("SHAP EXPLAINER CREATED")
                
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
                
                feature_names = self.feature_columns
                print(
                    "SHAP feature count:",
                    len(shap_val_array)
                )

                print(
                    "Column count:",
                    len(feature_names)
                )
                top_indices = np.argsort(np.abs(shap_val_array))[-5:][::-1]
                
                for idx in top_indices:
                    if idx >= len(feature_names):
                        continue
                    shap_top_features.append(
                        (
                            feature_names[idx],
                            abs(float(shap_val_array[idx]))
                        )
                    )
                    
                explanation_parts = [
                    f"{name} (importance: {abs(val):.2f})"
                    for name, val in shap_top_features
                ]
                shap_explanation = "Score driven by: " + ", ".join(explanation_parts)
            except Exception as e:
                print("===== XGBOOST FAILURE =====")
                print(traceback.format_exc())
                print(f"Warning: ML scoring failed: {e}")
                ml_score = static.permission_danger_score * 0.7 + static.api_suspicion_score * 0.3
                shap_top_features = [
                    ("permission_danger", static.permission_danger_score), 
                    ("api_suspicion", static.api_suspicion_score)
                ]
                shap_explanation = "Heuristic scoring applied (ML model execution failed)."
                xgb_probability = ml_score / 100.0
        else:
            ml_score = static.permission_danger_score * 0.7 + static.api_suspicion_score * 0.3
            shap_top_features = [("permission_danger", static.permission_danger_score), ("api_suspicion", static.api_suspicion_score)]
            xgb_probability = ml_score / 100.0
            
            
        dimension_scores = {
            "permission_abuse": static.permission_danger_score,
            "obfuscation": static.obfuscation_score,
            "behavioral_anomaly": dynamic.behavioural_anomaly_score,
            "ml_malware": ml_score,
            "developer_trust": 100.0 - static.cert_trust_score,
            "llm_severity": llm.severity_score * 100
        }
        
        WEIGHTS = {
            "permission_abuse": 0.10,
            "obfuscation": 0.10,
            "behavioral_anomaly": 0.15,
            "ml_malware": 0.45,
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
        if llm.verdict == "BLOCK":
            composite = min(100.0, composite + 10)
            boost_rules_applied.append(
                "LLM verdict BLOCK (+10)"
            )
        if dynamic.silent_install_attempted:
            composite = min(100.0, composite + 15)
            boost_rules_applied.append("Silent install attempted (+15)")
        
        if dynamic.root_detected:
            composite = min(100.0, composite + 15)
            boost_rules_applied.append("Root activity detected (+15)")

        if dynamic.shell_executed:
            composite = min(100.0, composite + 10)
            boost_rules_applied.append("Shell execution detected (+10)")

        if dynamic.dynamic_code_loaded:
            composite = min(100.0, composite + 10)
            boost_rules_applied.append("Dynamic code loading detected (+10)")

        # --- NEW ADVANCED INTEL BOOSTS ---
        
        # 1. Dropper / Embedded Payload Penalty
        if getattr(static, 'embedded_apks', 0) > 0 or getattr(static, 'embedded_dex', 0) > 0:
            payload_count = (
                getattr(static, 'embedded_apks', 0)
                + getattr(static, 'embedded_dex', 0)
            )
            payload_boost = min(
                20 + ((payload_count - 1) * 5),
                30
            )
            composite = min(100.0, composite + payload_boost)
            boost_rules_applied.append(f"Hidden executable payloads (Dropper behavior) ({payload_boost})")

        # 2. Packed/Encrypted Asset Penalty
        if getattr(static, 'encrypted_blobs', 0) > 0:
            composite = min(100.0, composite + 15)
            boost_rules_applied.append("Encrypted/Packed blobs found in resources (+15)")

        # 3. Sandbox Evasion / Anti-Analysis Penalty
        anti_analysis_score = getattr(static, 'anti_analysis_score', 0.0)
        if anti_analysis_score > 15:
            # Scale the boost penalty relative to how aggressively they are trying to hide
            evasion_boost = round(min(25.0, anti_analysis_score * 0.4), 1)
            composite = min(100.0, composite + evasion_boost)
            boost_rules_applied.append(f"Anti-analysis/evasion mechanisms detected (+{evasion_boost})")

        
        crypto_score = getattr(static,"crypto_score",0)
        if crypto_score > 40:
            crypto_boost = min(crypto_score * 0.15,10)
            composite = min(100.0,composite + crypto_boost)
            boost_rules_applied.append(f"Cryptographic obfuscation detected (+{crypto_boost:.1f})")

        if static.vt_malicious_count >= 5:
            composite = min(
                100.0,
                composite + 25
            )

            boost_rules_applied.append(
                "VirusTotal malicious detections (+25)"
            )
        
        if yara_result:
            composite = min(
                100.0,
                composite + yara_result.score_boost
            )

            if yara_result.matched_families:
                boost_rules_applied.append(
                    f"YARA matches: {', '.join(yara_result.matched_families)}"
                )
            
        action = self.get_action(composite)

        analysis_incomplete = (
            self.xgb_model is None
            or not llm.llm_available
        )

        if analysis_incomplete:
            boost_rules_applied.append(
                "Analysis incomplete (LLM unavailable)"
            )
        
        return RiskScore(
            composite_score=composite,
            action=action,
            dimension_scores=dimension_scores,
            ml_score=ml_score,
            shap_top_features=shap_top_features,
            shap_explanation=shap_explanation,
            boost_rules_applied=boost_rules_applied,
            xgb_probability=xgb_probability
        )
