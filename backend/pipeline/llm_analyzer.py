import time
import json
from dataclasses import dataclass, field
from typing import List
import google.generativeai as genai
import traceback

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
    from backend.pipeline.resilient_router import ResilientLLMRouter
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
        _model_default = getattr(config, 'LLM_MODEL', 'gemini-2.0-flash') if config else 'gemini-1.5-flash'
        self.api_key = api_key or _api_key_default
        self.model_name = model or _model_default
        print("Gemini key loaded:", bool(self.api_key))
        print("Using model:", self.model_name)
        if self.api_key:
            genai.configure(api_key=self.api_key)
            self.model = genai.GenerativeModel(self.model_name)
        else:
            self.model = None
        self.router = ResilientLLMRouter()

    def analyze(self, static: 'StaticFeatures', dynamic: 'DynamicFeatures', family=None, evidence=None, confidence_score=None) -> LLMFeatures:
        t0 = time.time()
        
        if self.model is None:
            print("Warning: LLM analysis unavailable (no API key), using static signals only")
            return self._get_fallback_features()

        # Step 1: Class Selection (mocked decompiled code for the prompt)
        formatted_class_code = static.decompiled_code

        # Step 2: Analysis Prompt
        system_prompt = """
        You are MobileGuard AI, a senior Android malware reverse engineer and threat intelligence analyst operating within a national-level Security Operations Centre (SOC).

You possess expert-level knowledge of:

- Android internals
- APK reverse engineering
- Banking trojans
- Overlay attacks
- Accessibility abuse
- SMS interception malware
- Spyware
- RATs (Remote Access Trojans)
- Credential theft
- Dynamic code loading
- Obfuscation techniques
- Anti-analysis mechanisms
- Android permissions
- Android IPC mechanisms
- Android security architecture
- Mobile threat intelligence

Your responsibility is to perform evidence-driven malware assessments of Android applications submitted for security review.

--------------------------------------------------
CORE ANALYSIS RULES
--------------------------------------------------

1. EVIDENCE OVER ASSUMPTION

Never speculate.

Every security claim must be supported by evidence extracted from the APK.

Evidence may include:

- Class names
- Method names
- API calls
- Permissions
- Intents
- Services
- Broadcast Receivers
- Content Providers
- URLs
- Domains
- IP addresses
- Cryptographic functions
- Reflection usage
- Native libraries
- String constants
- Network endpoints
- Dynamic loading mechanisms

If evidence is insufficient:

State:

"Insufficient evidence to support this conclusion."

Do not infer malicious intent without supporting artifacts.

--------------------------------------------------
2. DISTINGUISH CAPABILITY FROM INTENT
--------------------------------------------------

The existence of a capability does not prove maliciousness.

Examples:

READ_SMS alone is not malware.

AccessibilityService alone is not malware.

VPNService alone is not malware.

Overlay permissions alone are not malware.

Only elevate risk when multiple indicators form a coherent attack chain.

Explain the difference between:

- Benign capability
- Suspicious capability
- Malicious behavior

--------------------------------------------------
3. FALSE POSITIVE CONTROL
--------------------------------------------------

Always consider legitimate explanations.

Examples:

- Analytics SDKs
- Push notification frameworks
- Advertising SDKs
- Crash reporting tools
- Enterprise MDM software
- Accessibility tools
- Banking security frameworks

Do not classify software as malware solely because:

- It requests dangerous permissions
- It uses encryption
- It accesses the network
- It uses accessibility APIs
- It contains obfuscated code

Context matters.

--------------------------------------------------
4. ATTACK CHAIN RECONSTRUCTION
--------------------------------------------------

When possible, reconstruct the likely attack flow.

Example:

User installs APK
→ Accessibility permission requested
→ Overlay displayed over banking app
→ Credentials captured
→ Data transmitted to remote endpoint

Explain each step using observed evidence.

--------------------------------------------------
5. THREAT INTELLIGENCE MAPPING
--------------------------------------------------

Map observed behaviors to known malware techniques when supported.

Reference:

- MITRE ATT&CK Mobile techniques
- Android malware tradecraft
- Banking trojan patterns
- Credential theft workflows
- Spyware behaviors

Do not attribute malware families unless evidence strongly supports attribution.

--------------------------------------------------
6. CONFIDENCE SCORING
--------------------------------------------------

For every major conclusion provide:

Confidence:
HIGH
MEDIUM
LOW

HIGH:
Multiple independent indicators support conclusion.

MEDIUM:
Some evidence exists but gaps remain.

LOW:
Weak evidence or limited visibility.

--------------------------------------------------
7. ADVERSARIAL THINKING
--------------------------------------------------

Assume malware authors attempt to evade detection.

Look for:

- Reflection
- Dynamic class loading
- DexClassLoader
- PathClassLoader
- Runtime code execution
- String encryption
- Native code
- Anti-emulator checks
- Anti-debugging
- Delayed execution
- Obfuscation
- Packed payloads
- Remote configuration

Explain how these mechanisms affect confidence.

--------------------------------------------------
OUTPUT REQUIREMENTS
--------------------------------------------------

Generate the report using the following sections.

# Executive Summary

Brief assessment of overall risk.

# Verdict

One of:

APPROVE
MONITOR
ESCALATE
BLOCK

# Risk Level

LOW
MEDIUM
HIGH
CRITICAL

# Key Evidence

Bullet list of the strongest indicators discovered.

# Technical Findings

Detailed analysis referencing specific evidence.

# Attack Chain

Step-by-step reconstruction of likely behavior.

# MITRE ATT&CK Mobile Mapping

Relevant techniques and justification.

# Benign Explanations Considered

Alternative legitimate interpretations and why they were accepted or rejected.

# Confidence Assessment

Confidence level and rationale.

# Recommended Action

Specific SOC response recommendations.

--------------------------------------------------
FINAL RULE
--------------------------------------------------

You are a forensic analyst, not a prosecutor.

Your objective is to determine what the application can do, what it appears intended to do, and how confidently that conclusion is supported by evidence.

Prefer uncertainty over hallucination.
Prefer evidence over intuition.
Prefer precision over verbosity.
        """

        user_prompt = f"""
You are conducting a forensic review of an Android application.

Your objective is to determine:

1. What the application actually does.
2. What security risks are supported by evidence.
3. Whether observed behaviors are benign, suspicious, or malicious.
4. How confident you are in each conclusion.

--------------------------------------------------
APPLICATION METADATA
--------------------------------------------------

Package Name:
{static.package_name}

--------------------------------------------------
STATIC ANALYSIS SIGNALS
--------------------------------------------------

Dangerous Permissions:
{static.permission_list}

Suspicious APIs:
{static.top_apis}

High Entropy Strings:
{static.high_entropy_count}

Known C2 Matches:
{static.c2_hit_count}

Certificate Status:
{"Self-Signed" if static.is_self_signed else "Verified"}

--------------------------------------------------
THREAT INTELLIGENCE SIGNALS
--------------------------------------------------

Matched Malware Family:
{dynamic.matched_malware_family}

Similarity Score:
{dynamic.family_similarity_score:.0%}

--------------------------------------------------
RUNTIME ANALYSIS
--------------------------------------------------

Runtime Events:
{[e.event_type.value for e in dynamic.runtime_events[:50]]}

Behaviour Score:
{dynamic.behavioural_anomaly_score}

Collector Summary:
{dynamic.mapping_summary}

--------------------------------------------------
DECOMPILED SOURCE CODE
--------------------------------------------------

{formatted_class_code}


MALWARE FAMILY

{family.family if family else "Unknown"}

FAMILY CONFIDENCE

{family.confidence if family else 0}

CORRELATED FINDINGS

{json.dumps([
    {
        "finding": f.finding,
        "confidence": f.confidence,
        "severity": f.severity
    }
    for f in (evidence or [])
], indent=2)}

ENGINE CONFIDENCE

{confidence_score if confidence_score else 0}

--------------------------------------------------
ANALYSIS INSTRUCTIONS
--------------------------------------------------

CRITICAL:

Only report findings supported by evidence.

Evidence must include:

- Class names
- Method names
- Permissions
- APIs
- Receivers
- Services
- URLs
- Domains
- Strings
- Intents
- Reflection usage
- Dynamic loaders
- Native libraries

Do NOT make assumptions.

Do NOT infer malicious behavior without evidence.

Do NOT treat dangerous permissions alone as malicious.

Do NOT classify an application as malware solely because it:

- Uses networking
- Uses encryption
- Uses accessibility services
- Requests dangerous permissions
- Contains obfuscated code

Always distinguish between:

- Benign capability
- Suspicious capability
- Malicious behavior

If evidence is weak, lower confidence.

If evidence is absent, explicitly state that evidence is insufficient.

--------------------------------------------------
SCORING GUIDANCE
--------------------------------------------------

Severity Score (0.0-1.0):

0-0.2:
Likely benign

0.21-0.4:
Low risk

0.41-0.6:
Suspicious

0.61-0.8:
High risk

0.81-1.0:
Critical threat

Confidence (0.0-1.0):

1.0:
Multiple independent indicators directly support findings.

0.7:
Strong indicators but incomplete visibility.

0.5:
Moderate evidence.

0.3:
Weak evidence.

0.1:
Minimal evidence.

--------------------------------------------------
VERDICT RULES
--------------------------------------------------

APPROVE:
No meaningful threat indicators.

MONITOR:
Suspicious behaviors exist but insufficient evidence of malicious intent.

ESCALATE:
Multiple malicious indicators require analyst review.

BLOCK:
Strong evidence of credential theft, spyware behavior,
banking trojan activity, OTP interception, remote control,
overlay attacks, exfiltration, or known malware patterns.

--------------------------------------------------
JSON OUTPUT RULES
--------------------------------------------------

Return ONLY valid JSON.

No markdown.

No explanations outside JSON.

No code blocks.

The JSON must exactly match this schema:

{{
    "primary_function": "",

    "malicious_behaviors": [
        {{
            "behavior": "",
            "evidence": [
                ""
            ],
            "confidence": 0.0
        }}
    ],

    "data_collection": [
        {{
            "data_type": "",
            "collection_method": "",
            "usage_or_exfiltration": "",
            "evidence": [
                ""
            ]
        }}
    ],

    "obfuscation_techniques": [
        {{
            "technique": "",
            "evidence": [
                ""
            ]
        }}
    ],

    "attack_vectors": [
        {{
            "vector": "",
            "technical_explanation": "",
            "evidence": [
                ""
            ]
        }}
    ],

    "india_specific_risks": [
        {{
            "risk": "",
            "evidence": [
                ""
            ]
        }}
    ],

    "severity_score": 0.0,

    "confidence": 0.0,

    "verdict": "",

    "recommended_action": "",

    "executive_summary": "",

    "key_evidence": [
        ""
    ],

    "benign_explanations_considered": [
        ""
    ]
    
}}
"""

        try:
            print("===== ROUTING TO RESILIENT LLM INFRASTRUCTURE =====")
            
            data = self.router.analyze_malware(
                system_prompt=system_prompt,
                user_prompt_template=user_prompt, # Remove decompiled_code from your user_prompt string definition
                decompiled_code=static.decompiled_code 
            )
            
            if not data:
                raise ValueError("Router returned empty JSON dictionary.")

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

                hyp_data = self.router.analyze_malware(
                    system_prompt="You are a JSON generator. Return ONLY a JSON array of strings.",
                    user_prompt_template=hypotheses_prompt,
                    decompiled_code=""
                )

                if isinstance(hyp_data, list):
                    features.zero_day_hypotheses = hyp_data
                elif isinstance(hyp_data, dict) and "hypotheses" in hyp_data:
                    features.zero_day_hypotheses = hyp_data["hypotheses"]

        except Exception as e:
            print("===== LLM FAILURE =====")
            print(traceback.format_exc())
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
