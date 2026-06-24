from backend.plugins.plugin_base import PluginBase, PluginFinding, PluginMetadata

class AdvancedSpywareDetector(PluginBase):
    
    metadata = PluginMetadata(
        name="Advanced Commercial Spyware / Stalkerware",
        author="MobileGuard AI Core",
        version="1.2",
        description="Correlates mass-surveillance capabilities with active icon-hiding and stealth persistence mechanisms."
    )

    def analyze(self, static_features, dynamic_features):
        findings = []
        evidence = []
        confidence = 0.0

        perms = getattr(static_features, "permission_list", [])
        
        # 1. Mass Surveillance Capability Count
        surveillance_perms = {"RECORD_AUDIO", "CAMERA", "ACCESS_FINE_LOCATION", "READ_CONTACTS", "READ_CALL_LOG", "READ_SMS"}
        matched_perms = [p for p in perms if p in surveillance_perms]
        
        if len(matched_perms) >= 3:
            evidence.append(f"Capability: Requests mass surveillance matrix ({', '.join(matched_perms)})")
            confidence += 30.0
        elif len(matched_perms) < 3:
            # If it doesn't have at least 3 surveillance perms, it's not advanced spyware.
            return []

        # 2. Stealth Capability (The differentiator from legitimate comms apps)
        has_stealth = "PROCESS_OUTGOING_CALLS" in perms or "RECEIVE_BOOT_COMPLETED" in perms
        if has_stealth:
            confidence += 10.0

        # 3. Execution (The Kill Shot)
        icon_hidden = getattr(dynamic_features, "icon_hidden", False)
        mic_accessed = getattr(dynamic_features, "microphone_accessed", False)
        cam_accessed = getattr(dynamic_features, "camera_accessed", False)
        
        if icon_hidden:
            evidence.append("Execution: Sandbox observed the application actively hiding its launcher icon to evade uninstallation.")
            confidence += 40.0
            
        if mic_accessed or cam_accessed:
            evidence.append("Execution: Media hardware (Mic/Camera) engaged during headless sandbox execution.")
            confidence += 20.0

        # 4. Forensic Gate
        # Do NOT flag legitimate communication apps. We ONLY flag if the app hides its icon 
        # while possessing mass surveillance capabilities.
        if len(matched_perms) >= 3 and icon_hidden:
            findings.append(
                PluginFinding(
                    finding="Commercial Spyware / Stalkerware",
                    severity="CRITICAL",
                    confidence=min(confidence, 100.0),
                    evidence=evidence,
                    mitre_techniques=["T1429", "T1512", "T1430", "T1629"] # Audio, Video, Location, Icon Hiding
                )
            )

        return findings