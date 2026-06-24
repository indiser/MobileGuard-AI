import hashlib
import time
import os
import logging
from dataclasses import dataclass
from typing import List, Dict, Any, Tuple
from collections import Counter
import math
import re
from urllib.parse import urlparse
from fastapi import HTTPException
import magic
import numpy as np

# Import specific Android parsing modules, skipping the heavy 'AnalyzeAPK' wrapper
from androguard.core.bytecodes.apk import APK
from androguard.core.bytecodes.dvm import DalvikVMFormat

from backend.data.threat_intel import ThreatIntel
from backend.intel.anti_analysis_detector import AntiAnalysisDetector
from backend.intel.resource_analyzer import ResourceAnalyzer
from backend.intel.crypto_analyzer import CryptoAnalyzer

logging.getLogger("androguard.core.apk").setLevel(logging.ERROR)
logging.getLogger("androguard").setLevel(logging.ERROR)

@dataclass
class StaticFeatures:
    apk_hash: str
    package_name: str
    permission_list: List[str]
    permission_danger_score: float
    permission_count: int
    dangerous_permission_count: int
    suspicious_api_count: int
    api_suspicion_score: float
    top_apis: List[str]
    high_entropy_count: int
    obfuscation_score: float
    suspicious_urls: List[str]
    c2_hit_count: int
    is_self_signed: bool
    cert_trust_score: float
    has_native_code: bool
    native_risk_score: float
    receiver_list: List[str]
    service_list: List[str]
    graph_density: float
    graph_node_count: int
    graph_edge_count: int
    min_sdk: int
    decompiled_code: str
    target_sdk: int
    analysis_duration_ms: int
    vt_malicious_count: int
    vt_suspicious_count: int
    extracted_strings: List[str]

    anti_analysis_score: float
    anti_analysis_indicators: List[str]
    resource_score: float
    embedded_apks: int
    embedded_dex: int
    encrypted_blobs: int
    suspicious_resources: List[dict]

    crypto_score: float
    encrypted_string_count: int
    crypto_algorithms: List[str]
    crypto_indicators: List[str]
    crypto_ttps: List[str]
    hardcoded_secrets: List[str]

DANGEROUS_PERMISSIONS = {
    'READ_SMS': 5, 'RECEIVE_SMS': 5, 'SEND_SMS': 5,
    'BIND_ACCESSIBILITY_SERVICE': 5,
    'READ_CALL_LOG': 4, 'PROCESS_OUTGOING_CALLS': 4,
    'CAMERA': 3, 'RECORD_AUDIO': 3,
    'READ_CONTACTS': 3, 'READ_PHONE_STATE': 3,
    'SYSTEM_ALERT_WINDOW': 4, 'WRITE_SETTINGS': 3,
    'INSTALL_PACKAGES': 5, 'REQUEST_INSTALL_PACKAGES': 5,
    'RECEIVE_BOOT_COMPLETED': 3, 'FOREGROUND_SERVICE': 2,
    'READ_EXTERNAL_STORAGE': 2, 'WRITE_EXTERNAL_STORAGE': 2,
    'ACCESS_FINE_LOCATION': 3, 'INTERNET': 1,
    'NFC': 3, 'USE_BIOMETRIC': 3
}

SUSPICIOUS_API_PATTERNS = [
    'sendTextMessage', 'getSubscriberId', 'getDeviceId', 'getImei',
    'getRunningTasks', 'startActivity',
    'Runtime.exec', 'ProcessBuilder',
    'HttpURLConnection', 'getInputStream',
    'Class.forName', 'getDeclaredMethod',
    'getSystemService("accessibility")',
    'PackageInstaller', 'setComponentEnabledSetting'
]

URL_PATTERN = re.compile(r'https?://[^\s"\'<>]+')
IP_PATTERN = re.compile(r'\b\d{1,3}(\.\d{1,3}){3}\b')
C2_KEYWORDS = ['bot', 'cmd', 'command', 'payload', 'inject', 'hook']

KNOWN_MALICIOUS_LIBS = [
    'libdvm_hook.so', 'libinject.so', 'libsubstrate.so',
    'libxposed.so', 'libfrida-gadget.so'
]

# ---------------------------------------------------------------------------
# High-Performance Math & Parsing
# ---------------------------------------------------------------------------

def fast_high_entropy_count(strings: List[str]) -> int:
    """
    Vectorized Shannon entropy calculation. Filters strings via fast heuristics
    first ($O(1)$ length/space checks) before engaging numpy log math.
    """
    count = 0
    for s in strings:
        if type(s) != str:
            continue
            
        if 20 < len(s) < 1000 and " " not in s and not s.startswith("http"):
            try:
                arr = np.frombuffer(s.encode('utf-8'), dtype=np.uint8)
                _, counts = np.unique(arr, return_counts=True)
                probs = counts / len(arr)
                ent = -np.sum(probs * np.log2(probs))
                if ent > 4.5:
                    count += 1
            except Exception:
                pass
    return count

def extract_domain(url: str) -> str:
    try:
        parsed = urlparse(url)
        return parsed.netloc.lower()
    except Exception:
        return ""

class StaticAnalyzer:
    def __init__(self):
        self.intel = ThreatIntel()
        self.anti_analysis = AntiAnalysisDetector()
        self.resource_analyzer = ResourceAnalyzer()
        self.crypto_analyzer = CryptoAnalyzer()

    def analyze(self, apk_path: str) -> StaticFeatures:
        t0 = time.time()
        
        if not os.path.exists(apk_path):
            raise HTTPException(status_code=404, detail="File not found")
        
        file_size_mb = os.path.getsize(apk_path) / (1024 * 1024)
        if file_size_mb > 150:
            raise HTTPException(status_code=413, detail="File too large")
            
        try:
            magic_bytes = magic.from_file(apk_path, mime=True)
            if magic_bytes not in ['application/zip', 'application/java-archive', 'application/vnd.android.package-archive']:
                with open(apk_path, 'rb') as f:
                    if f.read(2) != b'PK':
                        raise HTTPException(status_code=422, detail="Invalid APK format")
        except Exception:
            pass
        
        sha256_hash = hashlib.sha256()
        with open(apk_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256_hash.update(chunk)
        apk_hash = sha256_hash.hexdigest()
        
        # 1. Parse Manifest ONLY (Lightning Fast)
        try:
            apk = APK(apk_path)
        except Exception as e:
            raise HTTPException(status_code=422, detail=f"Failed to parse APK: {str(e)}")
            
        permission_list = apk.get_permissions() or []
        clean_perms = [p.split('.')[-1] for p in permission_list]
        receiver_list = list(apk.get_receivers()) or []
        service_list = list(apk.get_services()) or []
        package_name = apk.get_package() or "unknown"
        
        min_sdk = int(apk.get_min_sdk_version() or 0) if apk.get_min_sdk_version() else 0
        target_sdk = int(apk.get_target_sdk_version() or 0) if apk.get_target_sdk_version() else 0

        # Certificate Parsing
        cert_names = []
        try:
            cert_names = apk.get_signature_names() or []
        except AttributeError:
            try:
                cert_names = list(apk.get_certificates_der_v2().keys()) or []
            except Exception:
                pass
        
        # 2. Permission Risk Scoring
        perm_weights = []
        dangerous_permission_count = 0
        for p in clean_perms:
            if p in DANGEROUS_PERMISSIONS:
                perm_weights.append(DANGEROUS_PERMISSIONS[p])
                dangerous_permission_count += 1
                
        combo_bonuses = 0
        if 'READ_SMS' in clean_perms and 'INTERNET' in clean_perms: combo_bonuses += 10
        if 'BIND_ACCESSIBILITY_SERVICE' in clean_perms and 'SYSTEM_ALERT_WINDOW' in clean_perms: combo_bonuses += 15
        if 'INSTALL_PACKAGES' in clean_perms and 'RECEIVE_BOOT_COMPLETED' in clean_perms: combo_bonuses += 12
        if 'RECORD_AUDIO' in clean_perms and 'CAMERA' in clean_perms and 'READ_CONTACTS' in clean_perms: combo_bonuses += 10
            
        theoretical_max = sum(DANGEROUS_PERMISSIONS.values()) + 47
        permission_danger_score = min(100.0, (sum(perm_weights) + combo_bonuses) / max(1, theoretical_max) * 100.0)
        
        # 3. Fast DEX Parsing (No Cross-Reference Graphing)
        strings = []
        suspicious_api_hits = set()
        in_degrees = Counter()
        code_chunks = []
        
        for dex_byte in apk.get_all_dex():
            try:
                dex = DalvikVMFormat(dex_byte)
            except Exception:
                continue
                
            # String Extraction
            strings.extend([s for s in dex.get_strings() if type(s) == str])
            
            # structural extraction for LLM (Bypass Java AST decompile)
            if len(code_chunks) < 200:
                for cls in dex.get_classes():
                    c_name = cls.get_name()
                    if c_name.startswith(("Ljava/", "Landroidx/", "Landroid/support/", "Lkotlin/")):
                        continue
                    
                    class_data = [f"Class: {c_name}"]
                    for method in cls.get_methods():
                        class_data.append(f"  -> {method.get_name()}")
                        
                    code_chunks.append("\n".join(class_data))
                    if len(code_chunks) >= 200:
                        break

            # API Call Resolution ($O(N)$ linear scan of Method IDs)
            for s in strings:
                for pat in SUSPICIOUS_API_PATTERNS:
                    if pat in s:
                        suspicious_api_hits.add(pat)
                        in_degrees[pat] += 1

        decompiled_code = "\n".join(code_chunks)
        suspicious_api_count = len(suspicious_api_hits)
        api_suspicion_score = min(100.0, suspicious_api_count * 8.0)
        top_apis = [k for k, v in in_degrees.most_common(10)]
        
        # We skipped graphing entirely, set defaults
        graph_node_count = 0
        graph_edge_count = 0
        graph_density = 0.0

        # 4. Math & Heuristics
        high_entropy_count = fast_high_entropy_count(strings)
        obfuscation_score = min(100.0, (high_entropy_count / max(len(strings), 1)) * 100.0)

        suspicious_urls = []
        for s in strings:
            if URL_PATTERN.search(s):
                suspicious_urls.append(s)

        c2_hit_count = 0
        vt_malicious_count = 0
        vt_suspicious_count = 0
        
        vt_result = self.intel.query_virustotal_hash(apk_hash)
        if vt_result:
            try:
                stats = vt_result["data"]["attributes"]["last_analysis_stats"]
                vt_malicious_count = stats.get("malicious", 0)
                vt_suspicious_count = stats.get("suspicious", 0)
            except Exception:
                pass

        suspicious_urls = list(set(suspicious_urls))
        for url in suspicious_urls:
            domain = extract_domain(url)
            if self.intel.is_malicious_domain(domain):
                c2_hit_count += 1
        
        # 5. Certificate Trust
        is_self_signed = False
        cert_trust_score = 100.0
        if cert_names:
            try:
                cert_info = apk.get_certificate(cert_names[0])
                if cert_info:
                    issuer = cert_info.issuer.human_friendly
                    subject = cert_info.subject.human_friendly
                    is_self_signed = (issuer == subject)
                    if is_self_signed: cert_trust_score -= 40
                    
                    try:
                        import datetime as _dt
                        nb = cert_info.not_valid_before.native if hasattr(cert_info.not_valid_before, 'native') else cert_info.not_valid_before
                        na = cert_info.not_valid_after.native if hasattr(cert_info.not_valid_after, 'native') else cert_info.not_valid_after
                        if nb is not None and na is not None:
                            if hasattr(nb, 'utcoffset') and nb.utcoffset() is not None: nb = nb.replace(tzinfo=None)
                            if hasattr(na, 'utcoffset') and na.utcoffset() is not None: na = na.replace(tzinfo=None)
                            if (_dt.datetime(*na.timetuple()[:6]) - _dt.datetime(*nb.timetuple()[:6])).days > 3650:
                                cert_trust_score -= 15
                    except Exception:
                        pass
                        
                    if 'debug' in issuer.lower(): cert_trust_score -= 30
                    if 'bank' in subject.lower() and 'bank' not in package_name.lower(): cert_trust_score -= 50
                    cert_trust_score = max(0.0, cert_trust_score)
            except Exception:
                cert_trust_score = 50.0
        else:
            cert_trust_score = 0.0
            
        # 6. Native Library Analysis
        has_native_code = False
        native_risk_score = 0.0
        try:
            so_files = [f for f in apk.get_files() if f.endswith('.so')]
            has_native_code = len(so_files) > 0
            if has_native_code:
                native_risk_score = 20.0
                for so in so_files:
                    if so.split('/')[-1] in KNOWN_MALICIOUS_LIBS:
                        native_risk_score += 30.0
                native_risk_score = min(100.0, native_risk_score)
        except Exception:
            pass

        # 7. Sub-Engine Invocation
        anti_analysis_result = self.anti_analysis.analyze(
            decompiled_code=decompiled_code,
            extracted_strings=strings 
        )
        
        resource_result = self.resource_analyzer.analyze(apk_path=apk_path)
        crypto_result = self.crypto_analyzer.analyze(decompiled_code, strings)

        analysis_duration_ms = int((time.time() - t0) * 1000)
        
        return StaticFeatures(
            apk_hash=apk_hash,
            package_name=package_name,
            permission_list=clean_perms,
            permission_danger_score=permission_danger_score,
            permission_count=len(clean_perms),
            decompiled_code=decompiled_code[:20000],
            dangerous_permission_count=dangerous_permission_count,
            suspicious_api_count=suspicious_api_count,
            api_suspicion_score=api_suspicion_score,
            top_apis=top_apis,
            high_entropy_count=high_entropy_count,
            obfuscation_score=obfuscation_score,
            suspicious_urls=suspicious_urls[:20],
            c2_hit_count=c2_hit_count,
            is_self_signed=is_self_signed,
            cert_trust_score=cert_trust_score,
            has_native_code=has_native_code,
            native_risk_score=native_risk_score,
            receiver_list=receiver_list,
            service_list=service_list,
            graph_density=graph_density,
            graph_node_count=graph_node_count,
            graph_edge_count=graph_edge_count,
            min_sdk=min_sdk,
            target_sdk=target_sdk,
            analysis_duration_ms=analysis_duration_ms,
            vt_malicious_count=vt_malicious_count,
            vt_suspicious_count=vt_suspicious_count,
            extracted_strings=strings[:5000],

            anti_analysis_score=anti_analysis_result.score,
            anti_analysis_indicators=anti_analysis_result.indicators,
            resource_score=resource_result.score,
            embedded_apks=resource_result.embedded_apks,
            embedded_dex=resource_result.embedded_dex,
            encrypted_blobs=resource_result.encrypted_blobs,
            suspicious_resources=[
                {"filename": f.filename, "reason": f.reason, "entropy": f.entropy}
                for f in resource_result.suspicious_files
            ],

            crypto_score=crypto_result.score,
            encrypted_string_count=crypto_result.encrypted_string_count,
            crypto_algorithms=crypto_result.crypto_algorithms,
            crypto_indicators=crypto_result.indicators,
            crypto_ttps=crypto_result.ttps,
            hardcoded_secrets=crypto_result.hardcoded_secrets
        )

if __name__ == "__main__":
    import sys
    import pprint
    if len(sys.argv) > 1:
        analyzer = StaticAnalyzer()
        res = analyzer.analyze(sys.argv[1])
        pprint.pprint(res)