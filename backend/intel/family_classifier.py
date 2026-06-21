from dataclasses import dataclass, field
from typing import Optional


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
# Rule definition
# Each rule declares which permissions / APIs it looks for, how many must
# match to fire, and what confidence that earns.
# ---------------------------------------------------------------------------

_RULES: list[dict] = [
    {
        "family": "BankBot-like",
        "required_permissions": {"READ_SMS", "BIND_ACCESSIBILITY_SERVICE"},
        "bonus_permissions": {"RECEIVE_SMS", "SEND_SMS", "REQUEST_INSTALL_PACKAGES"},
        "required_apis": set(),
        "bonus_apis": {"Cipher", "HttpsURLConnection"},
        "min_required": 2,          # all required signals must match
        "confidence_base": 0.75,
        "confidence_per_bonus": 0.05,
        "note": "Targets banking apps via SMS interception and accessibility overlays.",
    },
    {
        "family": "Spyware-like",
        "required_permissions": {"READ_CONTACTS", "ACCESS_FINE_LOCATION"},
        "bonus_permissions": {"READ_CALL_LOG", "RECORD_AUDIO", "CAMERA", "READ_EXTERNAL_STORAGE"},
        "required_apis": set(),
        "bonus_apis": {"TelephonyManager.getDeviceId", "LocationManager"},
        "min_required": 2,
        "confidence_base": 0.75,
        "confidence_per_bonus": 0.05,
        "note": "Exfiltrates user data including location, contacts, and media.",
    },
    {
        "family": "RAT-like",
        "required_permissions": set(),
        "bonus_permissions": {"INTERNET", "RECEIVE_BOOT_COMPLETED", "REQUEST_INSTALL_PACKAGES"},
        "required_apis": set(),
        "bonus_apis": set(),
        # RAT fires when *any* of these APIs appear
        "trigger_apis": {"Runtime.exec", "DexClassLoader", "ProcessBuilder", "ClassLoader"},
        "min_trigger_apis": 1,
        "confidence_base": 0.70,
        "confidence_per_bonus": 0.05,
        "note": "Remote access capability via dynamic code loading or shell execution.",
    },
    {
        "family": "Ransomware-like",
        "required_permissions": {"WRITE_EXTERNAL_STORAGE", "READ_EXTERNAL_STORAGE"},
        "bonus_permissions": {"REQUEST_INSTALL_PACKAGES", "RECEIVE_BOOT_COMPLETED"},
        "required_apis": set(),
        "bonus_apis": {"Cipher", "SecretKeySpec", "LockTaskMode"},
        "min_required": 2,
        "confidence_base": 0.70,
        "confidence_per_bonus": 0.05,
        "note": "Encrypts or locks user files/device for extortion.",
    },
]


class FamilyClassifier:
    """
    Classifies Android malware into known families based on permissions and
    suspicious API calls.

    Returns a ClassificationResult with a confidence score rather than a bare
    string so callers can make threshold-based decisions.
    """

    def __init__(self, confidence_threshold: float = 0.0):
        """
        Args:
            confidence_threshold: Minimum confidence required to return a
                non-Unknown result. Useful for high-precision pipelines.
        """
        self.confidence_threshold = confidence_threshold

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def classify(
        self,
        permissions: list[str],
        suspicious_apis: list[str],
    ) -> ClassificationResult:
        """
        Classify a sample and return the best-matching family.

        Args:
            permissions:    Android permission strings (e.g. "READ_SMS").
            suspicious_apis: Suspicious API or class names found in the APK.

        Returns:
            ClassificationResult for the top match, or Unknown if nothing fires.
        """
        perms = set(permissions)
        apis = set(suspicious_apis)

        candidates = [self._score_rule(rule, perms, apis) for rule in _RULES]
        candidates = [c for c in candidates if c is not None]

        if not candidates:
            return ClassificationResult(family="Unknown", confidence=0.0)

        best = max(candidates, key=lambda r: r.confidence)

        if best.confidence < self.confidence_threshold:
            return ClassificationResult(
                family="Unknown",
                confidence=best.confidence,
                note=f"Best match was {best.family!r} but below threshold.",
            )

        return best

    def classify_all(
        self,
        permissions: list[str],
        suspicious_apis: list[str],
    ) -> list[ClassificationResult]:
        """
        Return every family whose rule fired, sorted by confidence descending.
        Useful when a sample exhibits behaviour from multiple families.
        """
        perms = set(permissions)
        apis = set(suspicious_apis)

        results = [self._score_rule(rule, perms, apis) for rule in _RULES]
        results = [r for r in results if r is not None]
        return sorted(results, key=lambda r: r.confidence, reverse=True)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _score_rule(
        self,
        rule: dict,
        perms: set[str],
        apis: set[str],
    ) -> Optional[ClassificationResult]:
        signals: list[str] = []

        # --- required permissions (all must be present) ---
        required_perms = rule.get("required_permissions", set())
        matched_required = required_perms & perms
        if required_perms and len(matched_required) < rule.get("min_required", len(required_perms)):
            # Check whether this rule uses trigger_apis as an alternative path
            if "trigger_apis" not in rule:
                return None
        signals.extend(matched_required)

        # --- trigger APIs (any N must appear — used by RAT rule) ---
        trigger_apis = rule.get("trigger_apis", set())
        matched_triggers = trigger_apis & apis
        min_triggers = rule.get("min_trigger_apis", 0)
        if trigger_apis and len(matched_triggers) < min_triggers:
            # If required permissions also didn't fire, skip entirely
            if not matched_required or len(matched_required) < rule.get("min_required", len(required_perms)):
                return None
        signals.extend(matched_triggers)

        # Nothing at all matched
        if not signals:
            return None

        # --- bonus signals (each adds a small confidence bump) ---
        bonus_perms = rule.get("bonus_permissions", set()) & perms
        bonus_apis = rule.get("bonus_apis", set()) & apis
        bonus_count = len(bonus_perms) + len(bonus_apis)
        signals.extend(bonus_perms | bonus_apis)

        confidence = min(
            1.0,
            rule["confidence_base"] + bonus_count * rule.get("confidence_per_bonus", 0.0),
        )

        return ClassificationResult(
            family=rule["family"],
            confidence=round(confidence, 4),
            matched_signals=sorted(signals),
            note=rule.get("note"),
        )