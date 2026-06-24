from dataclasses import dataclass
from typing import List


@dataclass
class EvidenceFinding:
    finding: str
    confidence: int
    severity: str
    evidence: List[str]


class EvidenceEngine:

    def correlate(
        self,
        static_features,
        dynamic_events,
        yara_hits,
        mitre_hits,
        vt_results
    ):

        findings = []
        
        # Helper to safely extract lists from complex objects/dicts
        y_hits = getattr(yara_hits, 'matched_families', yara_hits) if yara_hits else []
        m_hits = getattr(mitre_hits, 'techniques', mitre_hits) if mitre_hits else []
        mitre_ids = [getattr(t, 'technique_id', str(t)) for t in m_hits]

        # ---------------------------------------------------------
        # Credential Theft & Overlay Attacks
        # ---------------------------------------------------------
        cred_evidence = []

        if "BIND_ACCESSIBILITY_SERVICE" in static_features.permission_list:
            cred_evidence.append("Static: Requests Accessibility Service")
        if "SYSTEM_ALERT_WINDOW" in static_features.permission_list:
            cred_evidence.append("Static: Requests Overlay Permission")
        if getattr(dynamic_events, "accessibility_service_abused", False):
            cred_evidence.append("Runtime: Accessibility Service Actively Abused")
        if getattr(dynamic_events, "overlay_detected", False):
            cred_evidence.append("Runtime: Malicious Overlay Displayed")
        if "T1411" in mitre_ids or "T1636.004" in mitre_ids:
            cred_evidence.append("Intel: MITRE ATT&CK Credential/Input Capture detected")

        has_runtime = any("Runtime:" in e for e in cred_evidence)
        has_intel = any("Intel:" in e for e in cred_evidence)

        # Demand a chain: Not just static permissions, but actual runtime execution or strong intel
        if len(cred_evidence) >= 2 and (has_runtime or has_intel):
            findings.append(
                EvidenceFinding(
                    finding="Overlay / Credential Theft Attack",
                    confidence=95 if has_runtime else 50, # Dropped from 75 to 50 without runtime
                    severity="CRITICAL" if has_runtime else "MEDIUM", # Dropped to MEDIUM without runtime
                    evidence=cred_evidence
                )
            )

        # ---------------------------------------------------------
        # Dynamic Payload Loading / Dropper
        # ---------------------------------------------------------
        loader_evidence = []

        if "REQUEST_INSTALL_PACKAGES" in static_features.permission_list:
            loader_evidence.append("Static: Can install other packages")
        if getattr(dynamic_events, "dynamic_code_loaded", False):
            loader_evidence.append("Runtime: Executed dynamic code loading (DexClassLoader)")
        if getattr(dynamic_events, "silent_install_attempted", False):
            loader_evidence.append("Runtime: Attempted silent package installation")
        if "T1407" in mitre_ids:
            loader_evidence.append("Intel: MITRE ATT&CK Download New Code detected")

        has_loader_runtime = any("Runtime:" in e for e in loader_evidence)

        if len(loader_evidence) >= 2 and (has_loader_runtime or any("Intel:" in e for e in loader_evidence)):
            findings.append(
                EvidenceFinding(
                    finding="Dropper / Dynamic Payload Loading",
                    confidence=90 if has_loader_runtime else 60,
                    severity="HIGH" if has_loader_runtime else "MEDIUM",
                    evidence=loader_evidence
                )
            )

        # ---------------------------------------------------------
        # Command And Control (C2) / Exfiltration
        # ---------------------------------------------------------
        c2_evidence = []

        if static_features.c2_hit_count > 0:
            c2_evidence.append(f"Static: {static_features.c2_hit_count} Hardcoded Malicious IPs/Domains")
        if getattr(dynamic_events, "c2_domains_hit", 0) > 0:
            c2_evidence.append(f"Runtime: Connected to {dynamic_events.c2_domains_hit} known C2 servers")
        if getattr(dynamic_events, "data_exfil_bytes", 0) > 0:
            c2_evidence.append(f"Runtime: Exfiltrated {dynamic_events.data_exfil_bytes} bytes of data")
        if len(y_hits) > 0:
            c2_evidence.append(
                f"Intel: YARA matched known malware signatures "
                f"({', '.join(y_hits[:2])})"
            )
            
        vt_malicious = vt_results.get("malicious", 0) if isinstance(vt_results, dict) else 0
        if vt_malicious > 0:
            c2_evidence.append(f"Intel: VirusTotal flagged by {vt_malicious} security vendors")

        if len(c2_evidence) >= 2:
            findings.append(
                EvidenceFinding(
                    finding="Command And Control (C2) Active",
                    confidence=98 if "Runtime:" in str(c2_evidence) else 85,
                    severity="CRITICAL",
                    evidence=c2_evidence
                )
            )

        # ---------------------------------------------------------
        # Remote Administration Trojan (RAT) / Privilege Escalation
        # ---------------------------------------------------------
        rat_evidence = []

        if getattr(dynamic_events, "root_detected", False):
            rat_evidence.append("Runtime: Attempted to execute su/root commands")
        if getattr(dynamic_events, "shell_executed", False):
            rat_evidence.append("Runtime: Unauthorized shell execution (Runtime.exec)")
        if getattr(dynamic_events, "icon_hidden", False):
            rat_evidence.append("Runtime: Application hid its launcher icon to evade uninstallation")
        if getattr(dynamic_events, "device_admin_requested", False):
            rat_evidence.append("Runtime: Attempted to hijack Device Administrator privileges")

        if len(rat_evidence) >= 2:
            findings.append(
                EvidenceFinding(
                    finding="Remote Access / Privilege Escalation",
                    confidence=95,
                    severity="CRITICAL",
                    evidence=rat_evidence
                )
            )

        # ---------------------------------------------------------
        # Spyware / Media Surveillance Activity
        # ---------------------------------------------------------
        spyware_evidence = []

        if "RECORD_AUDIO" in static_features.permission_list:
            spyware_evidence.append("Static: Microphone Access")

        if "CAMERA" in static_features.permission_list:
            spyware_evidence.append("Static: Camera Access")

        if getattr(dynamic_events, "microphone_accessed", False):
            spyware_evidence.append("Runtime: Microphone Activated")

        if getattr(dynamic_events, "camera_accessed", False):
            spyware_evidence.append("Runtime: Camera Activated")
            
        if "T1429" in mitre_ids or "T1512" in mitre_ids:
            spyware_evidence.append("Intel: MITRE ATT&CK Audio/Video Capture detected")

        has_spyware_runtime = any("Runtime:" in e for e in spyware_evidence)
        has_spyware_intel = any("Intel:" in e for e in spyware_evidence)

        # Demand verification. If it's just static permissions (e.g., WhatsApp, Zoom), 
        # downgrade the severity to prevent massive false positives.
        if len(spyware_evidence) >= 2 and (has_spyware_runtime or has_spyware_intel):
            findings.append(
                EvidenceFinding(
                    finding="Spyware / Media Surveillance Activity",
                    confidence=90 if has_spyware_runtime else 50,
                    severity="HIGH" if has_spyware_runtime else "MEDIUM",
                    evidence=spyware_evidence
                )
            )
        
        # ---------------------------------------------------------
        # Anti-Analysis / Sandbox Evasion
        # ---------------------------------------------------------
        anti_evidence = []
        anti_score = getattr(static_features, "anti_analysis_score", 0)

        if anti_score > 0:
            anti_evidence.append(f"Static: Anti-analysis heuristics triggered (Score: {anti_score:.1f})")

        indicators = getattr(static_features, "anti_analysis_indicators", [])
        if indicators:
            # Group them so it doesn't flood the report, but shows proof
            anti_evidence.append(f"Static: Evasion indicators found ({', '.join(indicators[:5])})")

        if "T1497" in mitre_ids or "T1406" in mitre_ids or "T1633" in mitre_ids:
            anti_evidence.append("Intel: MITRE ATT&CK Defense Evasion techniques mapped")

        # Did it actually try to hide its presence while running?
        if getattr(dynamic_events, "icon_hidden", False):
            anti_evidence.append("Runtime: Application hid its launcher icon to evade analysis/uninstallation")

        has_anti_runtime = any("Runtime:" in e for e in anti_evidence)
        has_anti_intel = any("Intel:" in e for e in anti_evidence)

        # Gate: If it's just a low-level root check (score < 20) with no intel/runtime, ignore it to prevent FPs.
        # If it has a high static score, it's MEDIUM. If it has actual runtime evasion, it's HIGH.
        if len(anti_evidence) >= 2 and (anti_score > 20 or has_anti_runtime or has_anti_intel):
            findings.append(
                EvidenceFinding(
                    finding="Anti-Analysis / Sandbox Evasion",
                    confidence=90 if has_anti_runtime else (70 if anti_score > 40 else 50),
                    severity="HIGH" if (has_anti_runtime or anti_score > 50) else "MEDIUM",
                    evidence=anti_evidence
                )
            )

        
        # ---------------------------------------------------------
        # Embedded Payload Deployment (Dropper)
        # ---------------------------------------------------------
        payload_evidence = []

        embedded_apks = getattr(static_features, "embedded_apks", 0)
        embedded_dex = getattr(static_features, "embedded_dex", 0)
        encrypted_blobs = getattr(static_features, "encrypted_blobs", 0)

        if embedded_apks > 0:
            payload_evidence.append(f"Static: {embedded_apks} embedded APK payload(s) detected via Magic Bytes")
        if embedded_dex > 0:
            payload_evidence.append(f"Static: {embedded_dex} embedded DEX payload(s) detected via Magic Bytes")
        if encrypted_blobs > 0:
            payload_evidence.append(f"Static: {encrypted_blobs} highly encrypted blob(s) in resources")

        # THE CRITICAL RUNTIME CHECK
        if getattr(dynamic_events, "dynamic_code_loaded", False):
            payload_evidence.append("Runtime: Actively loaded dynamic code (DexClassLoader/PathClassLoader)")
        
        if getattr(dynamic_events, "package_installed_silently", False):
            payload_evidence.append("Runtime: Attempted to silently install a secondary package")

        if "T1407" in mitre_ids or "T1623" in mitre_ids:
            payload_evidence.append("Intel: MITRE ATT&CK Payload Deployment/Execution mapped")

        has_payload_runtime = any("Runtime:" in e for e in payload_evidence)
        has_payload_intel = any("Intel:" in e for e in payload_evidence)

        # Gate: Demand verification. A static embedded DEX is only CRITICAL if it is actually 
        # dynamically loaded at runtime. Otherwise, it is downgraded to a MEDIUM risk anomaly.
        if len(payload_evidence) >= 2 and (has_payload_runtime or has_payload_intel or (embedded_apks + embedded_dex > 0)):
            findings.append(
                EvidenceFinding(
                    finding="Embedded Payload Deployment",
                    confidence=95 if has_payload_runtime else 60,
                    severity="CRITICAL" if has_payload_runtime else "MEDIUM",
                    evidence=payload_evidence
                )
            )
        
        # ---------------------------------------------------------
        # 1. Hardcoded Credentials / Secrets Exposure
        # ---------------------------------------------------------
        hardcoded_secrets = getattr(static_features, "hardcoded_secrets", [])
        
        if hardcoded_secrets:
            # Exposing secrets is a direct, critical finding on its own.
            # We don't need runtime correlation to know a leaked AWS key is fatal.
            findings.append(
                EvidenceFinding(
                    finding="Hardcoded Credentials / Secrets Exposure",
                    confidence=95,
                    severity="CRITICAL",
                    evidence=[f"Static: Exposed secret -> {s}" for s in hardcoded_secrets[:5]]
                )
            )

        # ---------------------------------------------------------
        # 2. Cryptographic Obfuscation / Ransomware Activity
        # ---------------------------------------------------------
        crypto_evidence = []
        crypto_score = getattr(static_features, "crypto_score", 0.0)
        crypto_ttps = getattr(static_features, "crypto_ttps", [])
        encrypted_strings = getattr(static_features, "encrypted_string_count", 0)

        # We explicitly IGNORE benign crypto_algorithms here. We only care about abuse.
        if crypto_ttps:
            crypto_evidence.append(f"Static: Cryptographic abuse patterns detected ({', '.join(crypto_ttps[:3])})")
            
        if encrypted_strings > 0:
            crypto_evidence.append(f"Static: {encrypted_strings} mathematically proven packed/encrypted string blob(s)")

        if "T1521" in mitre_ids or "T1406" in mitre_ids:
            crypto_evidence.append("Intel: MITRE ATT&CK Obfuscated/Encrypted payload/channel mapped")
            
        # Correlate highly encrypted blobs with the actual execution of dynamic code
        if getattr(dynamic_events, "dynamic_code_loaded", False) and encrypted_strings > 0:
             crypto_evidence.append("Runtime: Encrypted blobs strongly correlate with observed dynamic code execution")

        has_crypto_runtime = any("Runtime:" in e for e in crypto_evidence)
        has_crypto_intel = any("Intel:" in e for e in crypto_evidence)

        # Gate: We only flag crypto abuse if it has actual abuse patterns (TTPs) or high entropy strings.
        if len(crypto_evidence) >= 2 and (crypto_ttps or encrypted_strings > 0):
            
            # If the TTP specifically flags Ransomware logic or it dynamically executed, it's HIGH risk.
            is_high_risk = has_crypto_runtime or "File Encryption Loop (Ransomware)" in str(crypto_ttps)
            
            findings.append(
                EvidenceFinding(
                    finding="Cryptographic Obfuscation / Payload Encryption",
                    confidence=95 if has_crypto_runtime else (75 if crypto_score > 40 else 50),
                    severity="HIGH" if is_high_risk else "MEDIUM",
                    evidence=crypto_evidence
                )
            )

        return findings