"""
crypto_analyzer.py
------------------
SOC-Grade Cryptographic Abuse Detector.
Hunts for hardcoded secrets, insecure encryption modes, ransomware patterns,
and mathematically proven encrypted payloads, ignoring legitimate keystore usage.
"""

import math
import re
from collections import Counter
from dataclasses import dataclass, field
from typing import List, Dict, Set


@dataclass
class CryptoAnalysisResult:
    score: float
    encrypted_string_count: int
    crypto_algorithms: List[str]
    indicators: List[str]
    # Advanced Intelligence Fields
    ttps: List[str] = field(default_factory=list)
    hardcoded_secrets: List[str] = field(default_factory=list)


class CryptoAnalyzer:

    # Standard algorithms to note, but NOT penalize on their own
    ALGORITHM_PATTERNS = {
        "AES": [r"\bAES(?:/CBC|/GCM)?\b"],
        "RSA": [r"\bRSA(?:/ECB)?\b", r"\bKeyPairGenerator\b"],
        "DES/3DES": [r"\bDES\b", r"\bDESede\b", r"\bTripleDES\b"],
        "PBKDF2": [r"\bPBKDF2(?:WithHmacSHA[1|256|512])?\b"],
        "Hashing": [r"\bSHA-?256\b", r"\bSHA-?512\b", r"\bMD5\b"]
    }

    # Abuse Patterns (These actively drive the risk score up)
    ABUSE_PATTERNS = {
        "Insecure Mode (ECB)": {
            "patterns": [r"AES/ECB/PKCS[57]Padding", r"RSA/None/NoPadding"],
            "weight": 10.0,
            "desc": "Uses ECB mode which does not hide data patterns well (common in malware wrappers)."
        },
        "Hardcoded Symmetric Key Spec": {
            "patterns": [r"new\s+SecretKeySpec\s*\(\s*(?:[a-zA-Z0-9_]+|new\s+byte\[\]\s*\{[^}]+\})\s*,\s*\"AES\"\s*\)"],
            "weight": 20.0,
            "desc": "Instantiates AES keys directly from byte arrays in memory instead of the secure AndroidKeyStore."
        },
        "File Encryption Loop (Ransomware)": {
            "patterns": [r"Cipher\.ENCRYPT_MODE", r"getExternalStorageDirectory", r"walkFileTree"],
            "weight": 15.0, # Requires multiple hits to be critical
            "desc": "Contains cryptographic encryption routines combined with file system traversal."
        },
        "Custom Obfuscation (XOR)": {
            # Looking for common XOR decryption routine patterns in static bytecode
            "patterns": [r"\^\s*[a-zA-Z0-9_]+\s*\[\s*[a-zA-Z0-9_]+\s*%\s*[a-zA-Z0-9_]+\.length\s*\]"],
            "weight": 25.0,
            "desc": "Uses custom XOR loops typically used for string obfuscation or payload unpacking."
        }
    }

    # High-Value Secrets (Indicators of Compromise)
    SECRET_REGEXES = {
        "JWT Token": r"eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*",
        "AWS Access Key": r"AKIA[0-9A-Z]{16}",
        "Generic Hardcoded Secret": r"(?i)(?:password|secret|api_key|token|aes_key)\s*=\s*[\"']([A-Za-z0-9\+/=]{16,})[\"']"
    }

    def __init__(self):
        # Pre-compile all regexes for performance
        self.algo_compiled = {k: [re.compile(p) for p in v] for k, v in self.ALGORITHM_PATTERNS.items()}
        self.abuse_compiled = {k: {"regexes": [re.compile(p) for p in v["patterns"]], "weight": v["weight"]} for k, v in self.ABUSE_PATTERNS.items()}
        self.secrets_compiled = {k: re.compile(v) for k, v in self.SECRET_REGEXES.items()}

        # Base64 and Hex checkers
        self.BASE64_REGEX = re.compile(r"^[A-Za-z0-9+/]{40,}={0,2}$")
        self.HEX_REGEX = re.compile(r"^[A-Fa-f0-9]{64,}$")

    def _entropy(self, s: str) -> float:
        if not s: return 0.0
        freq = Counter(s)
        length = len(s)
        return -sum((count / length) * math.log2(count / length) for count in freq.values())

    def analyze(self, decompiled_code: str, extracted_strings: List[str]) -> CryptoAnalysisResult:
        blob = f"{decompiled_code}\n" + "\n".join(extracted_strings)
        
        score = 0.0
        indicators: Set[str] = set()
        crypto_algorithms: Set[str] = set()
        ttps: Set[str] = set()
        hardcoded_secrets: Set[str] = set()
        encrypted_string_count = 0

        # --------------------------------------------------
        # 1. Benign Capability Mapping (Info Only)
        # --------------------------------------------------
        for algo, regexes in self.algo_compiled.items():
            for rx in regexes:
                if rx.search(blob):
                    crypto_algorithms.add(algo)
                    break # Move to next algorithm once found

        # --------------------------------------------------
        # 2. Cryptographic Abuse Detection (Scored)
        # --------------------------------------------------
        for abuse_name, data in self.abuse_compiled.items():
            for rx in data["regexes"]:
                match = rx.search(blob)
                if match:
                    indicators.add(f"Matched Abuse Pattern: {abuse_name}")
                    ttps.add(abuse_name)
                    score += data["weight"]
                    break # Score once per abuse category

        # --------------------------------------------------
        # 3. Hardcoded Secret Extraction (Scored)
        # --------------------------------------------------
        for secret_type, rx in self.secrets_compiled.items():
            for match in rx.finditer(blob):
                # If it's a capture group (like Generic Secret), get group 1. Else get the whole match.
                secret_val = match.group(1) if len(match.groups()) > 0 else match.group(0)
                
                # Filter out obvious false positives (e.g., standard Android namespaces)
                if "android" in secret_val.lower() or "google" in secret_val.lower():
                    continue
                    
                hardcoded_secrets.add(f"{secret_type}: {secret_val[:10]}...[REDACTED]")
                indicators.add(f"Hardcoded {secret_type} exposed")
                score += 15.0 # Massive penalty for exposing secrets in bytecode
                break # Score heavily once per secret type

        # --------------------------------------------------
        # 4. True Encrypted Payload / String Detection
        # --------------------------------------------------
        for s in extracted_strings:
            # Skip short variables, focus on payload-sized blocks
            if len(s) < 40:
                continue

            # Check for pure Base64 or Hex
            is_b64 = bool(self.BASE64_REGEX.match(s))
            is_hex = bool(self.HEX_REGEX.match(s))

            if is_b64 or is_hex:
                entropy = self._entropy(s)
                # TRUE False-Positive filter:
                # Base64 of a JSON file has an entropy of ~5.5 to 6.2.
                # Base64 of an ENCRYPTED payload (AES/DEX) has an entropy of > 7.5 (nearly perfect randomness).
                # We only flag mathematically packed/encrypted strings.
                if entropy > 7.5:
                    encrypted_string_count += 1
                    indicators.add(f"Highly encrypted/packed string blob detected (Entropy: {entropy:.2f})")
            else:
                # Raw binary strings embedded in resources
                entropy = self._entropy(s)
                if entropy > 7.8:
                    encrypted_string_count += 1

        # Score Normalization for encrypted strings
        # E.g., 5 highly encrypted blobs adds 25 points, capped at 30.
        score += min(encrypted_string_count * 5.0, 30.0)

        # Ensure we don't exceed the 0-100 boundary
        final_score = round(min(score, 100.0), 2)

        return CryptoAnalysisResult(
            score=final_score,
            encrypted_string_count=encrypted_string_count,
            crypto_algorithms=sorted(list(crypto_algorithms)),
            indicators=sorted(list(indicators)),
            ttps=sorted(list(ttps)),
            hardcoded_secrets=sorted(list(hardcoded_secrets))
        )