"""
anti_analysis_detector.py
-------------------------
Detects sandbox evasion, root detection, anti-debugging, and hooking framework
presence using strict regex boundaries and severity-weighted TTPs.
"""

from dataclasses import dataclass, field
from typing import List, Dict
import re

@dataclass
class EvasionTTP:
    name: str
    severity: str
    confidence: float
    matched_patterns: List[str]

@dataclass
class AntiAnalysisResult:
    score: float
    indicators: List[str]
    ttps: List[EvasionTTP] = field(default_factory=list)

# ---------------------------------------------------------------------------
# Strict Regex Patterns (with \b boundaries to prevent substring false positives)
# ---------------------------------------------------------------------------

_CATEGORIES = {
    "Emulator Evasion": {
        "severity": "MEDIUM",
        "patterns": [
            r"\bro\.kernel\.qemu\b",
            r"\bgoldfish\b",
            r"\branchu\b",
            r"\bsdk_gphone\b",
            r"\bgeneric_x86\b",
            r"\bBuild\.FINGERPRINT.*(?:generic|unknown|test)\b",
            r"\bBuild\.MODEL.*(?:Emulator|Android SDK)\b",
            r"QEmuEnv",
            r"isEmulator"
        ]
    },
    "Anti-Debugging": {
        "severity": "HIGH",
        "patterns": [
            r"\bDebug\.isDebuggerConnected\b",
            r"\bwaitForDebugger\b",
            r"\bandroid\.os\.Debug\b",
            r"\bTracerPid\b",
            r"\bptrace\b",
            r"\bandroid\.os\.Debug\.waitForDebugger\b"
        ]
    },
    "Root Detection": {
        "severity": "MEDIUM",  # Many benign apps use this (banks, DRM), hence MEDIUM
        "patterns": [
            r"/system/xbin/su\b",
            r"/system/bin/su\b",
            r"\bwhich su\b",
            r"\bbusybox\b",
            r"\bmagisk\b",
            r"\bsupersu\b",
            r"\bro\.secure\s*=\s*0\b",
            r"\btest-keys\b"
        ]
    },
    "Hooking & Instrumentation": {
        "severity": "CRITICAL",
        "patterns": [
            r"\bfrida-server\b",
            r"\bgum-js-loop\b",
            r"\bre\.frida\.server\b",
            r"\bde\.robv\.android\.xposed\b",
            r"\bXposedBridge\b",
            r"\bXposedHelpers\b",
            r"\bedxposed\b",
            r"\bLSPosed\b",
            r"\bSubstrate\b"
        ]
    },
    "Anti-Tamper / Packer": {
        "severity": "HIGH",
        "patterns": [
            r"\bcheckSignature\b",
            r"\bverifySignature\b",
            r"\bPackageManager\.GET_SIGNATURES\b",
            r"\bLcom/secneo/apkwrapper\b",     # DexGuard / SecNeo
            r"\bLcom/tencent/stub\b",          # Tencent Legu
            r"\bLqihoo/util\b"                 # Qihoo 360
        ]
    }
}

class AntiAnalysisDetector:
    def __init__(self):
        # Pre-compile regexes for performance
        self.compiled_rules = {
            category: {
                "severity": data["severity"],
                "regexes": [re.compile(p, re.IGNORECASE) for p in data["patterns"]]
            }
            for category, data in _CATEGORIES.items()
        }

    def analyze(self, decompiled_code: str, extracted_strings: list[str]) -> AntiAnalysisResult:
        indicators = []
        ttps = []
        score = 0.0

        # Create a single massive string buffer, but we use regex boundaries to search it safely
        blob = f"{decompiled_code}\n" + "\n".join(extracted_strings)

        for category, rule_data in self.compiled_rules.items():
            matched_patterns = []
            
            for rx in rule_data["regexes"]:
                match = rx.search(blob)
                if match:
                    matched_patterns.append(match.group(0))

            if matched_patterns:
                # Deduplicate matched strings
                matched_patterns = list(set(matched_patterns))
                indicators.extend(matched_patterns)
                
                severity = rule_data["severity"]
                if severity == "CRITICAL":
                    score += 40.0
                elif severity == "HIGH":
                    score += 25.0
                elif severity == "MEDIUM":
                    score += 15.0

                ttps.append(EvasionTTP(
                    name=category,
                    severity=severity,
                    confidence=0.9, # High confidence due to strict regex
                    matched_patterns=matched_patterns
                ))

        # Hard cap at 100
        score = min(score, 100.0)

        return AntiAnalysisResult(
            score=score,
            indicators=sorted(set(indicators)),
            ttps=ttps
        )