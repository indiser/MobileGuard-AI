"""
family_classifier.py
--------------------
Heuristic fallback classifier for MobileGuard AI.
Used to determine the behavioral archetype of an APK when YARA and Threat Intel
fail to identify an exact malware family.
"""

from dataclasses import dataclass, field
from typing import Optional, Set

@dataclass
class ClassificationResult:
    family: str
    confidence: float          # 0.0 – 1.0
    matched_signals: list[str] = field(default_factory=list)
    note: Optional[str] = None

    def __repr__(self) -> str:
        pct = f"{self.confidence:.0%}"
        signals = ", ".join(self.matched_signals) if self.matched_signals else "none"
        return (
            f"ClassificationResult(family={self.family!r}, "
            f"confidence={pct}, signals=[{signals}])"
        )

# ---------------------------------------------------------------------------
# Advanced Behavioral Archetypes & Hardcoded Signatures
# ---------------------------------------------------------------------------

_RULES: list[dict] = [
    {
        "family": "Cerberus/Anubis-Style (Banking Trojan)",
        # A true modern banking trojan attack chain
        "required_permissions": {"BIND_ACCESSIBILITY_SERVICE", "SYSTEM_ALERT_WINDOW"},
        "bonus_permissions": {"RECEIVE_SMS", "READ_SMS", "WAKE_LOCK", "REQUEST_IGNORE_BATTERY_OPTIMIZATIONS"},
        "required_apis": set(),
        "bonus_apis": {
            "getSystemService(\"accessibility\")", 
            "WindowManager.addView", # Drawing the overlay
            "MediaProjectionManager", # Screen recording
            "SmsManager"
        },
        "suspicious_strings": {"payload", "bot", "inject", "VNC", "hideApp"},
        "min_required_perms": 2,          
        "confidence_base": 0.80,
        "confidence_per_bonus": 0.05,
        "note": "Exhibits the classic Accessibility + Overlay attack chain used to steal credentials and bypass 2FA.",
    },
    {
        "family": "SpyNote/Metasploit-Style (Advanced RAT)",
        "required_permissions": set(),
        "bonus_permissions": {"RECORD_AUDIO", "CAMERA", "ACCESS_FINE_LOCATION", "READ_CONTACTS"},
        "required_apis": {"Runtime.exec"}, # Must be capable of executing shell commands
        "bonus_apis": {
            "ProcessBuilder", 
            "Camera.open", 
            "AudioRecord.startRecording",
            "DexClassLoader"
        },
        "suspicious_strings": {
            "com.metasploit.stage", "spynote", "meterpreter", "reverse_tcp"
        },
        "min_required_perms": 0,
        "confidence_base": 0.75,
        "confidence_per_bonus": 0.05,
        "note": "Combines shell execution capabilities with massive data-harvesting permissions.",
    },
    {
        "family": "Dropper/Loader Framework",
        "required_permissions": {"REQUEST_INSTALL_PACKAGES"},
        "bonus_permissions": {"INTERNET", "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE"},
        "required_apis": set(),
        "bonus_apis": {
            "DexClassLoader", 
            "PathClassLoader", 
            "PackageInstaller", 
            "Context.startActivity"
        },
        "suspicious_strings": {
            ".apk", "classes.dex", "base.apk", "install", "download"
        },
        "min_required_perms": 1,
        "confidence_base": 0.70,
        "confidence_per_bonus": 0.05,
        "note": "Designed to bypass static analysis by downloading and dynamically loading malicious code at runtime.",
    },
    {
        "family": "Toll Fraud / Premium SMS Dialer",
        "required_permissions": {"SEND_SMS"},
        "bonus_permissions": {"RECEIVE_SMS", "READ_PHONE_STATE", "BILLING"},
        "required_apis": {"SmsManager.sendTextMessage"},
        "bonus_apis": {"abortBroadcast", "ConnectivityManager"},
        "suspicious_strings": {"subscribe", "premium", "confirm", "WAP"},
        "min_required_perms": 1,
        "confidence_base": 0.85,
        "confidence_per_bonus": 0.05,
        "note": "Automatically sends SMS messages to premium-rate numbers and attempts to hide the confirmation replies.",
    },
    {
        "family": "Aggressive Adware / Hidden Ad-Fraud",
        # Real adware needs to survive reboots and draw over other apps
        "required_permissions": {"INTERNET", "SYSTEM_ALERT_WINDOW"},
        "bonus_permissions": {"RECEIVE_BOOT_COMPLETED", "WAKE_LOCK", "FOREGROUND_SERVICE", "INSTALL_SHORTCUT"},
        "required_apis": set(),
        "bonus_apis": {
            "WindowManager.addView",       # Drawing the out-of-context ads
            "setComponentEnabledSetting",  # Used to hide the launcher icon
            "WebView.loadUrl",             # Loading the ad payload
            "WebView.addJavascriptInterface" # Often used for silent click-fraud
        },
        "suspicious_strings": {
            "hideIcon", 
            "out_of_app", 
            "background_ad", 
            "Airpush",      # Known aggressive ad network
            "StartApp",     # Known aggressive ad network
            "RevMob",       # Known aggressive ad network
            "IronSource"
        },
        "min_required_perms": 2,          
        "confidence_base": 0.70,
        "confidence_per_bonus": 0.05,
        "note": "Flags out-of-context advertising and ad-fraud. Looks for overlay permissions combined with icon-hiding and invisible WebView capabilities, distinguishing it from legitimate in-app monetization."
    }
]

class FamilyClassifier:
    """
    Classifies Android malware into behavioral archetypes.
    For precise family attribution, rely on the pipeline's YaraEngine.
    """

    def __init__(self, confidence_threshold: float = 0.80):
        self.confidence_threshold = confidence_threshold

    def classify(
        self,
        permissions: list[str],
        suspicious_apis: list[str],
        strings: list[str] = None, # Added strings parameter to cross-reference static artifacts
        runtime_events: dict | None = None
    ) -> ClassificationResult:
        
        perms = set(permissions)
        apis = set(suspicious_apis)
        strings_set = set(strings) if strings else set()

        candidates = [self._score_rule(rule, perms, apis, strings_set, runtime_events or {}) for rule in _RULES]
        candidates = [c for c in candidates if c is not None]

        if not candidates:
            return ClassificationResult(
                family="Unknown (Heuristic)",
                confidence=0.50,
                note="No specific behavioral archetype matched. Defer to ML and LLM analysis."
            )

        best = max(candidates, key=lambda r: r.confidence)

        if best.confidence < self.confidence_threshold:
            return ClassificationResult(
                family="Unknown",
                confidence=best.confidence,
                note=f"Best match was {best.family!r} but below threshold ({best.confidence:.2f}).",
            )

        return best

    def _score_rule(
        self,
        rule: dict,
        perms: Set[str],
        apis: Set[str],
        strings: Set[str],
        runtime_events : dict
    ) -> Optional[ClassificationResult]:
        signals: list[str] = []

        # 1. Evaluate Required Permissions
        required_perms = rule.get("required_permissions", set())
        matched_required_perms = required_perms & perms
        if required_perms and len(matched_required_perms) < rule.get("min_required_perms", len(required_perms)):
            return None
        signals.extend(matched_required_perms)

        # 2. Evaluate Required APIs
        required_apis = rule.get("required_apis", set())
        matched_required_apis = required_apis & apis
        if required_apis and len(matched_required_apis) < len(required_apis):
            return None
        signals.extend(matched_required_apis)

        # 3. Direct String Hit (Massive Confidence Boost)
        rule_strings = rule.get("suspicious_strings", set())
        # Check if any rule string is a substring of any extracted string
        matched_strings = {rs for rs in rule_strings for s in strings if rs.lower() in s.lower()}
        signals.extend(matched_strings)

        if not signals and not matched_strings:
            return None

        # 4. Tally Bonuses
        bonus_perms = rule.get("bonus_permissions", set()) & perms
        bonus_apis = rule.get("bonus_apis", set()) & apis
        bonus_count = len(bonus_perms) + len(bonus_apis) + (len(matched_strings)) # Strings carry double weight

        signals.extend(bonus_perms | bonus_apis)

        runtime_signals = []

        if runtime_events.get("overlay_detected"):
            runtime_signals.append("Runtime: Overlay Displayed")

        if runtime_events.get("accessibility_service_abused"):
            runtime_signals.append("Runtime: Accessibility Abuse")

        if runtime_events.get("shell_executed"):
            runtime_signals.append("Runtime: Shell Executed")

        signals.extend(runtime_signals)
        
        runtime_bonus = 0.0

        if runtime_events.get("accessibility_service_abused"):
            runtime_bonus += 0.10

        if runtime_events.get("overlay_detected"):
            runtime_bonus += 0.10

        if runtime_events.get("shell_executed"):
            runtime_bonus += 0.15

        if runtime_events.get("dynamic_code_loaded"):
            runtime_bonus += 0.15

        if runtime_events.get("c2_domains_hit"):
            runtime_bonus += 0.20

        raw_confidence = rule["confidence_base"] + (bonus_count * rule.get("confidence_per_bonus", 0.05))

        if not runtime_signals and not matched_strings:
            raw_confidence = min(raw_confidence, 0.60)
        
        confidence = min(1.0, raw_confidence + runtime_bonus)

        return ClassificationResult(
            family=rule["family"],
            confidence=round(confidence, 4),
            matched_signals=sorted(list(set(signals))),
            note=rule.get("note"),
        )