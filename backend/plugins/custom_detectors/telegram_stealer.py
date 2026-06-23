import re
from backend.plugins.plugin_base import PluginBase, PluginFinding, PluginMetadata

class TelegramStealerDetector(PluginBase):
    
    metadata = PluginMetadata(
        name="Telegram C2 Info-Stealer",
        author="MobileGuard AI Core",
        version="1.0",
        description="Detects malware using the Telegram Bot API as a free command and control (C2) exfiltration endpoint."
    )

    # Matches the exact Telegram Bot API structure: api.telegram.org/bot<TOKEN>/sendMessage
    TELEGRAM_API_REGEX = re.compile(r"api\.telegram\.org/bot[0-9]{8,10}:[a-zA-Z0-9_-]{35}/(?:sendMessage|sendDocument)", re.IGNORECASE)

    def analyze(self, static_features, dynamic_features):
        findings = []
        evidence = []
        confidence = 0.0

        # 1. Capability
        perms = getattr(static_features, "permission_list", [])
        if "INTERNET" not in perms:
            return [] # Can't exfiltrate without internet
            
        has_data = "READ_SMS" in perms or "READ_CONTACTS" in perms or "READ_EXTERNAL_STORAGE" in perms
        if has_data:
            confidence += 20.0

        # 2. Intent (Hardcoded Bot API)
        strings = getattr(static_features, "extracted_strings", [])
        matched_bots = set()
        
        for s in strings:
            if type(s) is str and len(s) < 200:
                for match in self.TELEGRAM_API_REGEX.findall(s):
                    matched_bots.add(match)

        if len(matched_bots) > 0:
            evidence.append("Targeting: Hardcoded Telegram Bot API endpoints found in binary.")
            
            # Extract and redact the token for the SOC report
            for bot in matched_bots:
                redacted = re.sub(r"(bot[0-9]{8,10}:[a-zA-Z0-9_-]{5})[a-zA-Z0-9_-]{30}", r"\1...[REDACTED]", bot)
                evidence.append(f"Indicator: {redacted}")
                
            confidence += 60.0

        # 3. Execution 
        domains_contacted = getattr(dynamic_features, "network_domains_contacted", [])
        telegram_contacted = any("api.telegram.org" in d for d in domains_contacted)
        
        if telegram_contacted:
            evidence.append("Execution: Sandbox intercepted live outbound traffic to Telegram Bot API.")
            confidence += 20.0

        # 4. Forensic Gate
        # Finding a hardcoded bot token that ends in /sendMessage inside an APK is a 
        # guaranteed sign of an info-stealer.
        if len(matched_bots) > 0:
            findings.append(
                PluginFinding(
                    finding="Telegram C2 Info-Stealer Exfiltration",
                    severity="CRITICAL" if telegram_contacted else "HIGH",
                    confidence=min(confidence, 100.0),
                    evidence=evidence,
                    mitre_techniques=["T1437", "T1041"] # Application Layer Protocol, Exfiltration Over C2
                )
            )

        return findings