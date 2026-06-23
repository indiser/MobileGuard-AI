import re
from backend.plugins.plugin_base import PluginBase, PluginFinding, PluginMetadata

class ClipboardHijackerDetector(PluginBase):
    
    # 1. STRICT METADATA
    # This ensures the orchestrator knows exactly what is running and who wrote it.
    metadata = PluginMetadata(
        name="Crypto-Clipper / Clipboard Hijacker",
        author="MobileGuard AI Core",
        version="1.0",
        description="Detects background clipboard monitoring combined with hardcoded cryptocurrency wallet addresses."
    )

    # Compile regexes at the class level for performance.
    # Matches common Bitcoin (P2PKH, P2SH, Bech32) and Ethereum addresses.
    BTC_REGEX = re.compile(r"\b(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}\b")
    ETH_REGEX = re.compile(r"\b0x[a-fA-F0-9]{40}\b")

    def analyze(self, static_features, dynamic_features):
        findings = []
        evidence = []
        confidence = 0.0

        # ---------------------------------------------------------
        # STEP 1: SAFE EXTRACTION
        # Never assume a field exists. Always use getattr() with safe defaults.
        # ---------------------------------------------------------
        perms = getattr(static_features, "permission_list", [])
        strings = getattr(static_features, "extracted_strings", [])
        runtime_clipboard = getattr(dynamic_features, "clipboard_hijack_detected", False)
        runtime_services = getattr(dynamic_features, "mapping_summary", {}).get("services", 0)

        # ---------------------------------------------------------
        # STEP 2: CAPABILITY (Do they have the tools?)
        # ---------------------------------------------------------
        # To effectively hijack a clipboard, an app usually needs to run in the 
        # background (RECEIVE_BOOT_COMPLETED) or draw over the screen to stay active.
        has_background_persistence = "RECEIVE_BOOT_COMPLETED" in perms or runtime_services > 0
        
        if has_background_persistence:
            confidence += 15.0

        # ---------------------------------------------------------
        # STEP 3: INTENT / TARGETING (Do they have the motive?)
        # ---------------------------------------------------------
        matched_wallets = set()
        for s in strings:
            if type(s) is str and len(s) < 150:
                if self.BTC_REGEX.search(s) or self.ETH_REGEX.search(s):
                    matched_wallets.add(s)

        if len(matched_wallets) > 0:
            evidence.append(f"Targeting: Hardcoded crypto wallets found ({len(matched_wallets)} unique).")
            confidence += 35.0

        # ---------------------------------------------------------
        # STEP 4: RUNTIME EXECUTION (Did they actually pull the trigger?)
        # ---------------------------------------------------------
        if runtime_clipboard:
            evidence.append("Execution: Sandbox dynamically observed aggressive clipboard reads/writes.")
            confidence += 40.0

        # ---------------------------------------------------------
        # STEP 5: THE FORENSIC GATE
        # ---------------------------------------------------------
        # We DO NOT flag the app just because it has a Bitcoin address in its strings 
        # (it could be a legitimate crypto wallet app).
        # We ONLY flag it if it has hardcoded wallets AND is caught abusing the clipboard.
        
        if len(matched_wallets) > 0 and runtime_clipboard:
            findings.append(
                PluginFinding(
                    finding="Clipboard Crypto-Hijacking (Crypto-Clipper)",
                    severity="CRITICAL",
                    confidence=min(confidence + 10.0, 100.0), # Bonus for completing the chain
                    evidence=evidence,
                    mitre_techniques=["T1115", "T1636"] # Clipboard Data, Data from Local System
                )
            )

        return findings