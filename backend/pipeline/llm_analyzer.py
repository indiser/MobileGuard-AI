import time
import json
from dataclasses import dataclass, field
from typing import List
import google.generativeai as genai

try:
    from backend import config
except ImportError:
    try:
        import config  # type: ignore
    except ImportError:
        config = None  # type: ignore

# Import the feature dataclasses to type hint
try:
    from backend.pipeline.static_analyzer import StaticFeatures
except ImportError:
    pass
    
try:
    from backend.pipeline.dynamic_analyzer import DynamicFeatures
except ImportError:
    pass

@dataclass
class LLMFeatures:
    primary_function: str
    malicious_behaviors: List[str]
    data_collection: List[str]
    obfuscation_techniques: List[str]
    attack_vectors: List[str]
    india_specific_risks: List[str]
    severity_score: float              # 0.0-1.0
    confidence: float                  # 0.0-1.0
    verdict: str
    recommended_action: str
    executive_summary: str
    zero_day_hypotheses: List[str] = field(default_factory=list)
    llm_available: bool = True
    analysis_duration_ms: int = 0

class LLMAnalyzer:
    def __init__(self, api_key: str = None, model: str = None):
        _api_key_default = getattr(config, 'GEMINI_API_KEY', '') if config else ''
        _model_default = getattr(config, 'LLM_MODEL', 'gemini-1.5-pro') if config else 'gemini-1.5-pro'
        self.api_key = api_key or _api_key_default
        self.model_name = model or _model_default
        if self.api_key:
            genai.configure(api_key=self.api_key)
            self.model = genai.GenerativeModel(self.model_name)
        else:
            self.model = None

    def analyze(self, static: 'StaticFeatures', dynamic: 'DynamicFeatures') -> LLMFeatures:
        t0 = time.time()
        
        if not self.model:
            print("Warning: LLM analysis unavailable (no API key), using static signals only")
            return self._get_fallback_features()

        # Step 1: Class Selection (mocked decompiled code for the prompt)
        formatted_class_code = "// Decompiled code snippet placeholder\nclass MainActivity {\n  void onReceive() { ... }\n}"

        # Step 2: Analysis Prompt
        system_prompt = """
        You are an elite Android malware analyst at a national cybersecurity
        agency. You have 15 years of experience with banking trojans, spyware,
        SMS stealers, and overlay attack frameworks.

        You are analysing a suspicious Android application submitted by
        Bank of India's Security Operations Centre.

        Your analysis must be precise, evidence-based, and actionable.
        Never speculate without evidence from the code.
        Never produce generic statements — cite specific class names,
        method names, API calls, or string literals from the code.
        """

        user_prompt = f"""
        Analyse these decompiled Android classes from APK: {static.package_name}

        STATIC SIGNALS ALREADY DETECTED:
        - Dangerous permissions: {static.permission_list}
        - Suspicious APIs found: {static.top_apis}
        - High entropy strings: {static.high_entropy_count}
        - C2 IP matches: {static.c2_hit_count}
        - Certificate: {'self-signed' if static.is_self_signed else 'verified'}
        - Matched malware family: {dynamic.matched_malware_family} ({dynamic.family_similarity_score:.0%} similarity)

        DECOMPILED CODE:
        {formatted_class_code}

        Return ONLY a valid JSON object with exactly these fields:
        {{
            "primary_function": "one sentence describing what this app really does",
            "malicious_behaviors": [
            "specific behavior 1 with evidence: class/method name",
            "specific behavior 2 with evidence: class/method name"
            ],
            "data_collection": [
            "what data is collected and how it is used or exfiltrated"
            ],
            "obfuscation_techniques": [
            "specific obfuscation methods detected with evidence"
            ],
            "attack_vectors": [
            "specific attack vector with technical explanation"
            ],
            "india_specific_risks": [
            "risks specific to Indian banking users, UPI, OTP interception etc."
            ],
            "severity_score": 0.0,
            "confidence": 0.0,
            "verdict": "",
            "recommended_action": "",
            "executive_summary": "2-3 sentence summary for a bank executive"
        }}
        """

        try:
            full_prompt = system_prompt + "\n\n" + user_prompt
            response = self.model.generate_content(full_prompt)
            response_text = response.text
            
            # extract JSON
            if "{" in response_text and "}" in response_text:
                json_str = response_text[response_text.find("{"):response_text.rfind("}")+1]
                data = json.loads(json_str)
            else:
                raise ValueError("No JSON found in response")

            features = LLMFeatures(
                primary_function=data.get("primary_function", ""),
                malicious_behaviors=data.get("malicious_behaviors", []),
                data_collection=data.get("data_collection", []),
                obfuscation_techniques=data.get("obfuscation_techniques", []),
                attack_vectors=data.get("attack_vectors", []),
                india_specific_risks=data.get("india_specific_risks", []),
                severity_score=float(data.get("severity_score", 0.0)),
                confidence=float(data.get("confidence", 0.0)),
                verdict=data.get("verdict", "UNKNOWN"),
                recommended_action=data.get("recommended_action", ""),
                executive_summary=data.get("executive_summary", "")
            )

            # Step 3: Zero-Shot Novel Threat Analysis
            # If static ml_score < 0.4 AND llm severity_score > 0.6
            # (We don't have ml_score here, so we will just check severity score)
            if features.severity_score > 0.6 and dynamic.family_similarity_score < 0.4:
                hypotheses_prompt = """
                This application has not matched known malware families with
                high confidence. Based on the following code patterns, generate
                3 threat hypotheses ranked by likelihood. For each: name it,
                describe the attack chain, estimate impact on Indian banking users.
                Return ONLY a JSON array of strings.
                """
                hyp_response = self.model.generate_content(hypotheses_prompt)
                hyp_text = hyp_response.text
                if "[" in hyp_text and "]" in hyp_text:
                    hyp_json_str = hyp_text[hyp_text.find("["):hyp_text.rfind("]")+1]
                    features.zero_day_hypotheses = json.loads(hyp_json_str)

        except Exception as e:
            print(f"Warning: LLM analysis failed: {str(e)}")
            features = self._get_fallback_features()

        features.analysis_duration_ms = int((time.time() - t0) * 1000)
        return features

    def _get_fallback_features(self) -> LLMFeatures:
        return LLMFeatures(
            primary_function="Unknown",
            malicious_behaviors=[],
            data_collection=[],
            obfuscation_techniques=[],
            attack_vectors=[],
            india_specific_risks=[],
            severity_score=0.0,
            confidence=0.0,
            verdict="UNKNOWN",
            recommended_action="",
            executive_summary="LLM Analysis unavailable.",
            llm_available=False
        )
