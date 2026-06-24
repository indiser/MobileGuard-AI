import re
from backend.plugins.plugin_base import PluginBase, PluginFinding, PluginMetadata

class BankingTrojanDetector(PluginBase):
    
    metadata = PluginMetadata(
        name="Advanced Banking Trojan Correlator",
        author="MobileGuard AI Core",
        version="2.0",
        description="Detects modern overlay-based banking trojans using regex boundaries and runtime correlation."
    )

    # Use word boundaries (\b) to prevent "potpie" from triggering "otp"
    TARGETING_REGEX = re.compile(
        r"\b(otp|2fa|upi|bank|finance|wallet|credentials|login|password|com\.sbi\.|com\.hdfc\.)\b", 
        re.IGNORECASE
    )

    def analyze(self, static_features, dynamic_features):
        findings = []
        evidence = []
        confidence = 0.0

        # 1. Capability Check
        perms = getattr(static_features, "permission_list", [])
        has_overlay = "SYSTEM_ALERT_WINDOW" in perms
        has_a11y = "BIND_ACCESSIBILITY_SERVICE" in perms
        
        if has_overlay:
            evidence.append("Capability: Can draw overlays (SYSTEM_ALERT_WINDOW)")
            confidence += 20.0
        if has_a11y:
            evidence.append("Capability: Can intercept UI nodes (BIND_ACCESSIBILITY_SERVICE)")
            confidence += 20.0

        # 2. Targeting Check (Strict boundaries)
        strings = getattr(static_features, "extracted_strings", [])
        matched_targets = set()
        
        for s in strings:
            if type(s) is str and len(s) < 100:
                for match in self.TARGETING_REGEX.findall(s):
                    matched_targets.add(match.lower())

        if len(matched_targets) >= 3:
            evidence.append(f"Targeting: Banking/Auth artifacts found ({', '.join(list(matched_targets)[:4])})")
            confidence += 30.0

        # 3. Execution Verification (The Game Changer)
        runtime_overlay = getattr(dynamic_features, "overlay_detected", False)
        runtime_a11y = getattr(dynamic_features, "accessibility_service_abused", False)
        
        if runtime_overlay:
            evidence.append("Execution: Sandbox observed unauthorized overlay window drawn.")
            confidence += 15.0
        if runtime_a11y:
            evidence.append("Execution: Sandbox observed active abuse of Accessibility hooks.")
            confidence += 15.0

        # Evaluation Gate
        # Only trigger if they have the tools AND the targets.
        if has_overlay and has_a11y and len(matched_targets) >= 3:
            
            # If the sandbox caught them doing it, it's a critical, confirmed threat.
            is_critical = runtime_overlay or runtime_a11y
            
            findings.append(
                PluginFinding(
                    finding="Overlay-Based Banking Trojan Activity",
                    severity="CRITICAL" if is_critical else "HIGH",
                    confidence=min(confidence, 100.0),
                    evidence=evidence,
                    mitre_techniques=["T1411", "T1636.003"]
                )
            )

        return findings