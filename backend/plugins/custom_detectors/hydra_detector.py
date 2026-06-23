import re
from backend.plugins.plugin_base import PluginBase, PluginFinding, PluginMetadata

class HydraTrojanDetector(PluginBase):
    
    metadata = PluginMetadata(
        name="Hydra Banking Trojan",
        author="MobileGuard AI Core",
        version="1.0",
        description="Detects Hydra-style malware by identifying fake Play Protect overlays and Device Admin hijack attempts."
    )

    # Hydra uses fake Play Protect screens and targets specific global bank package namespaces
    # Also uses SOCKS5 proxies or TeamViewer for deep persistence.
    HYDRA_REGEX = re.compile(r"\b(play_protect|google_protect|update_play_services|socks5|teamviewer|com\.anydesk)\b", re.IGNORECASE)

    def analyze(self, static_features, dynamic_features):
        findings = []
        evidence = []
        confidence = 0.0

        perms = getattr(static_features, "permission_list", [])
        
        # 1. Capability
        has_device_admin = "BIND_DEVICE_ADMIN" in perms
        has_overlay = "SYSTEM_ALERT_WINDOW" in perms
        
        if has_device_admin: confidence += 20.0
        if has_overlay: confidence += 15.0

        # 2. Intent
        strings = getattr(static_features, "extracted_strings", [])
        matched_indicators = set()
        
        for s in strings:
            if type(s) is str and len(s) < 100:
                for match in self.HYDRA_REGEX.findall(s):
                    matched_indicators.add(match.lower())

        if len(matched_indicators) >= 2:
            evidence.append(f"Targeting: Hydra-associated strings/targets found ({', '.join(list(matched_indicators))})")
            confidence += 30.0

        # 3. Execution
        runtime_admin = getattr(dynamic_features, "device_admin_requested", False)
        runtime_overlay = getattr(dynamic_features, "overlay_detected", False)
        
        if runtime_admin:
            evidence.append("Execution: Sandbox captured an attempt to hijack Device Administrator privileges.")
            confidence += 25.0
        if runtime_overlay:
            evidence.append("Execution: Unauthorized overlay window drawn (Likely fake Play Protect screen).")
            confidence += 10.0

        # 4. Forensic Gate
        if has_device_admin and len(matched_indicators) >= 2:
            findings.append(
                PluginFinding(
                    finding="Hydra Banking Trojan Activity",
                    severity="CRITICAL" if runtime_admin else "HIGH",
                    confidence=min(confidence, 100.0),
                    evidence=evidence,
                    mitre_techniques=["T1411", "T1624"] # Input Capture, Device Admin Hijack
                )
            )

        return findings