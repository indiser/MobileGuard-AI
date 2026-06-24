import re
from backend.plugins.plugin_base import PluginBase, PluginFinding, PluginMetadata

class CerberusTrojanDetector(PluginBase):
    
    metadata = PluginMetadata(
        name="Cerberus / Alien Banking Trojan",
        author="MobileGuard AI Core",
        version="1.1",
        description="Hunts for Cerberus variants by correlating VNC screen-streaming, 2FA theft targets, and Accessibility abuse."
    )

    # Cerberus specifically targets Google Authenticator and uses distinct VNC/ScreenCast modules
    TARGET_REGEX = re.compile(r"\b(com\.google\.android\.apps\.authenticator2|cerberus|alien|screencast|vnc_service|payload_json)\b", re.IGNORECASE)

    def analyze(self, static_features, dynamic_features):
        findings = []
        evidence = []
        confidence = 0.0

        # 1. Capability extraction
        perms = getattr(static_features, "permission_list", [])
        apis = getattr(static_features, "top_apis", [])
        
        has_a11y = "BIND_ACCESSIBILITY_SERVICE" in perms
        has_projection = any("MediaProjection" in api for api in apis)
        
        if has_a11y:
            confidence += 15.0
        if has_projection:
            confidence += 15.0

        # 2. Intent (The Arsenal)
        strings = getattr(static_features, "extracted_strings", [])
        matched_targets = set()
        
        for s in strings:
            if type(s) is str and len(s) < 150:
                for match in self.TARGET_REGEX.findall(s):
                    matched_targets.add(match.lower())

        if len(matched_targets) >= 2:
            evidence.append(f"Targeting: Cerberus/Alien artifacts found ({', '.join(list(matched_targets))})")
            confidence += 30.0

        # 3. Execution (The Sandbox Proof)
        runtime_a11y = getattr(dynamic_features, "accessibility_service_abused", False)
        
        if runtime_a11y:
            evidence.append("Execution: Sandbox dynamically observed aggressive Accessibility node reading/writing.")
            confidence += 35.0

        # 4. Forensic Gate
        # Must have the artifacts AND the Accessibility capability to even be considered.
        if has_a11y and len(matched_targets) >= 2:
            is_critical = runtime_a11y and has_projection
            
            findings.append(
                PluginFinding(
                    finding="Cerberus/Alien Banking Trojan Activity",
                    severity="CRITICAL" if is_critical else "HIGH",
                    confidence=min(confidence, 100.0),
                    evidence=evidence,
                    mitre_techniques=["T1411", "T1636.003", "T1512"] # Credential Access, MFA Interception, Video Capture
                )
            )

        return findings