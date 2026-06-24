from backend.plugins.plugin_base import PluginBase, PluginFinding, PluginMetadata

class RansomwareDetector(PluginBase):
    
    metadata = PluginMetadata(
        name="Crypto-Ransomware & Wiper Hunter",
        author="MobileGuard AI Core",
        version="1.1",
        description="Correlates mass storage access with aggressive cryptographic looping."
    )

    def analyze(self, static_features, dynamic_features):
        findings = []
        evidence = []
        
        perms = getattr(static_features, "permission_list", [])
        apis = getattr(static_features, "top_apis", [])
        
        # Capability
        can_read_files = "READ_EXTERNAL_STORAGE" in perms or "MANAGE_EXTERNAL_STORAGE" in perms
        can_write_files = "WRITE_EXTERNAL_STORAGE" in perms or "MANAGE_EXTERNAL_STORAGE" in perms
        can_lock_device = "DISABLE_KEYGUARD" in perms or "SYSTEM_ALERT_WINDOW" in perms
        
        # Action
        has_crypto_apis = any("Cipher" in api or "SecretKeySpec" in api for api in apis)
        has_file_traversal = any("walkFileTree" in api or "listFiles" in api or "getExternalStorageDirectory" in api for api in apis)
        
        if can_read_files and can_write_files and has_crypto_apis and has_file_traversal:
            evidence.extend([
                "Capability: Broad access to external storage files.",
                "Capability: Cryptographic libraries (Cipher/SecretKeySpec) present in API list.",
                "Behavior: Bulk file system traversal APIs detected."
            ])
            
            if can_lock_device:
                evidence.append("Capability: Can draw over other apps or disable keyguard (Lock-screen tactic).")
                
            findings.append(
                PluginFinding(
                    finding="Mobile Ransomware / Mass File Encryption",
                    severity="CRITICAL",
                    confidence=85.0 if can_lock_device else 75.0,
                    evidence=evidence,
                    mitre_techniques=["T1486", "T1446"]
                )
            )

        return findings