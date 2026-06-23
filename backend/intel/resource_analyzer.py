"""
resource_analyzer.py
--------------------
Hunts for hidden payloads, embedded APKs, and encrypted droppers.
Bypasses file extensions and uses magic byte header analysis combined with
entropy to find malware hiding in the assets/ directory.
"""

import os
import zipfile
import math
from collections import Counter
from dataclasses import dataclass, field
from typing import List, Dict

@dataclass
class SuspiciousAsset:
    filename: str
    reason: str
    entropy: float

@dataclass
class ResourceAnalysisResult:
    embedded_apks: int
    embedded_dex: int
    encrypted_blobs: int
    suspicious_files: List[SuspiciousAsset] = field(default_factory=list)
    score: float = 0.0

def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = Counter(data)
    length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())

class ResourceAnalyzer:
    # We explicitly IGNORE these for entropy checks because they are naturally compressed
    KNOWN_COMPRESSED_EXTS = {
        ".png", ".jpg", ".jpeg", ".webp", ".gif", 
        ".mp3", ".mp4", ".ogg", ".wav", 
        ".zip", ".gz", ".rar", ".7z", ".pdf", ".woff", ".woff2"
    }

    # Explicitly suspicious extensions
    SUSPICIOUS_EXTENSIONS = {
        ".dex", ".jar", ".apk", ".bin", ".dat", ".enc", ".payload", ".so"
    }

    def analyze(self, apk_path: str) -> ResourceAnalysisResult:
        embedded_apks = 0
        embedded_dex = 0
        encrypted_blobs = 0
        suspicious_files: List[SuspiciousAsset] = []
        score = 0.0

        try:
            with zipfile.ZipFile(apk_path, "r") as apk:
                for name in apk.namelist():
                    lower_name = name.lower()
                    ext = os.path.splitext(lower_name)[1]
                    
                    is_in_assets = lower_name.startswith("assets/") or lower_name.startswith("res/raw/")
                    
                    try:
                        # Read the first few bytes for Magic Header analysis, plus full data for entropy
                        data = apk.read(name)
                        file_size = len(data)
                        
                        # 1. MAGIC BYTE ANALYSIS (Bypassing fake extensions)
                        if file_size > 4:
                            magic_bytes = data[:4]
                            
                            # Check if it's an APK pretending to be something else (PK zip header)
                            if magic_bytes == b"PK\x03\x04" and ext not in [".apk", ".zip", ".jar"]:
                                embedded_apks += 1
                                score += 20
                                suspicious_files.append(SuspiciousAsset(
                                    filename=name, reason="Hidden APK/ZIP (Magic Bytes 'PK')", entropy=shannon_entropy(data)
                                ))
                                continue
                                
                            # Check if it's a DEX pretending to be something else
                            if magic_bytes.startswith(b"dex\n") and ext != ".dex":
                                embedded_dex += 1
                                score += 40
                                suspicious_files.append(SuspiciousAsset(
                                    filename=name, reason="Hidden DEX payload (Magic Bytes 'dex')", entropy=shannon_entropy(data)
                                ))
                                continue

                        # 2. OVERT SUSPICIOUS EXTENSIONS
                        # Ignore the primary classes.dex or architecture .so files, look for nested ones
                        if ext in self.SUSPICIOUS_EXTENSIONS:
                            if not (lower_name.startswith("lib/") and ext == ".so") and lower_name != "classes.dex":
                                reason = "Embedded executable/payload"
                                if ext == ".apk": embedded_apks += 1; score += 20
                                elif ext == ".dex": embedded_dex += 1; score += 20
                                else: score += 10
                                
                                suspicious_files.append(SuspiciousAsset(
                                    filename=name, reason=reason, entropy=shannon_entropy(data)
                                ))
                                continue

                        # 3. ENTROPY ANALYSIS (The Smart Way)
                        # Only check if it's in a suspicious directory, large enough to be a payload,
                        # and NOT a known compressed media file.
                        if is_in_assets and file_size > 4096 and ext not in self.KNOWN_COMPRESSED_EXTS:
                            entropy = shannon_entropy(data)
                            # True encrypted payloads usually have an entropy > 7.8
                            if entropy > 7.8:
                                encrypted_blobs += 1
                                score += 15
                                suspicious_files.append(SuspiciousAsset(
                                    filename=name, reason=f"Highly encrypted/packed blob (Entropy: {entropy:.2f})", entropy=entropy
                                ))

                    except Exception:
                        pass # Corrupted file in ZIP, skip

        except Exception:
            pass # Invalid APK/ZIP

        # Cap score at 100
        score = min(score, 100.0)

        # Sort by most suspicious (highest entropy) and cap output size
        suspicious_files.sort(key=lambda x: x.entropy, reverse=True)

        return ResourceAnalysisResult(
            embedded_apks=embedded_apks,
            embedded_dex=embedded_dex,
            encrypted_blobs=encrypted_blobs,
            suspicious_files=suspicious_files[:25],
            score=score
        )