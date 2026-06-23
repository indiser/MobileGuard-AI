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
from androguard.misc import AnalyzeAPK
from backend.data.threat_intel import ThreatIntel
from backend.intel.anti_analysis_detector import AntiAnalysisDetector
from backend.intel.resource_analyzer import ResourceAnalyzer
from backend.intel.crypto_analyzer import CryptoAnalyzer

# Suppress androguard's "Requested API level X is larger than maximum" warning
logging.getLogger("androguard.core.apk").setLevel(logging.ERROR)
logging.getLogger("androguard").setLevel(logging.ERROR)

@dataclass
class StaticFeatures:
    apk_hash: str
    package_name: str
    permission_list: List[str]
    permission_danger_score: float    # 0-100
    permission_count: int
    dangerous_permission_count: int
    suspicious_api_count: int
    api_suspicion_score: float        # 0-100
    top_apis: List[str]
    high_entropy_count: int
    obfuscation_score: float          # 0-100
    suspicious_urls: List[str]
    c2_hit_count: int
    is_self_signed: bool
    cert_trust_score: float           # 0-100 (higher = more trusted)
    has_native_code: bool
    native_risk_score: float          # 0-100
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

IGNORE_APIS = [
    "kotlin/jvm/internal/Intrinsics",
    "java/lang/Object",
    "java/lang/StringBuilder",
    "androidx/",
    "kotlinx/",
    "java/util/",
    "java/lang/",
    "java/io/",
    "java/net/",
    "android/view/",
    "android/widget/",
    "android/content/",
    "android/util/",
    "android/graphics/",
    "android/os/",
]

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
BASE64_PATTERN = re.compile(r'[A-Za-z0-9+/]{40,}={0,2}')
KEY_PATTERN = re.compile(r'(password|secret|apikey|token)[\s=:]+\S+', re.IGNORECASE)
C2_KEYWORDS = ['bot', 'cmd', 'command', 'payload', 'inject', 'hook']

KNOWN_MALICIOUS_LIBS = [
    'libdvm_hook.so', 'libinject.so', 'libsubstrate.so',
    'libxposed.so', 'libfrida-gadget.so'
]

def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = Counter(s)
    length = len(s)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())

def extract_domain(url: str) -> str:
    try:
        parsed = urlparse(url)
        return parsed.netloc.lower()
    except Exception:
        return ""

decompiled_code = ""

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
                    header = f.read(2)
                    if header != b'PK':
                        raise HTTPException(status_code=422, detail="Invalid APK format")
        except Exception:
            with open(apk_path, 'rb') as f:
                header = f.read(2)
                if header != b'PK':
                    raise HTTPException(status_code=422, detail="Invalid APK format")
        
        sha256_hash = hashlib.sha256()
        with open(apk_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256_hash.update(chunk)
        apk_hash = sha256_hash.hexdigest()
        
        try:
            apk, dex, analysis = AnalyzeAPK(apk_path)
            code_chunks = []
            if dex:
                for cls in dex:
                    try:
                        src = cls.get_source()
                        if src:
                            code_chunks.append(src)
                    except:
                        pass
            decompiled_code = "\n".join(code_chunks[:20])
        except Exception as e:
            raise HTTPException(status_code=422, detail=f"Failed to parse APK: {str(e)}")
            
        # get_permissions() returns the permissions the app *uses* (from the manifest).
        # get_declared_permissions() returns custom permissions the app defines — not what we want.
        permission_list = apk.get_permissions() or []
        clean_perms = [p.split('.')[-1] for p in permission_list]
        
        receiver_list = list(apk.get_receivers()) or []
        service_list = list(apk.get_services()) or []
        
        try:
            min_sdk = int(apk.get_min_sdk_version() or 0)
        except Exception:
            min_sdk = 0
            
        try:
            target_sdk = int(apk.get_target_sdk_version() or 0)
        except Exception:
            target_sdk = 0

        # androguard 3.x: get_signature_names() was renamed to get_certificates_der_v2()
        # Use a safe fallback chain to handle API differences across versions.
        cert_names = []
        try:
            cert_names = apk.get_signature_names() or []
        except AttributeError:
            try:
                cert_names = list(apk.get_certificates_der_v2().keys()) or []
            except Exception:
                cert_names = []
        package_name = apk.get_package() or "unknown"
        
        perm_weights = []
        dangerous_permission_count = 0
        for p in clean_perms:
            if p in DANGEROUS_PERMISSIONS:
                perm_weights.append(DANGEROUS_PERMISSIONS[p])
                dangerous_permission_count += 1
                
        combo_bonuses = 0
        if 'READ_SMS' in clean_perms and 'INTERNET' in clean_perms:
            combo_bonuses += 10
        if 'BIND_ACCESSIBILITY_SERVICE' in clean_perms and 'SYSTEM_ALERT_WINDOW' in clean_perms:
            combo_bonuses += 15
        if 'INSTALL_PACKAGES' in clean_perms and 'RECEIVE_BOOT_COMPLETED' in clean_perms:
            combo_bonuses += 12
        if 'RECORD_AUDIO' in clean_perms and 'CAMERA' in clean_perms and 'READ_CONTACTS' in clean_perms:
            combo_bonuses += 10
            
        theoretical_max = sum(DANGEROUS_PERMISSIONS.values()) + 47
        permission_danger_score = min(100.0, (sum(perm_weights) + combo_bonuses) / max(1, theoretical_max) * 100.0)
        
        suspicious_api_hits = set()
        suspicious_api_count = 0
        in_degrees = Counter()
        unique_nodes = set()
        unique_edges = set()
        
        if analysis:
            for method in analysis.get_methods():
                try:
                    m = method.get_method()
                    m_name = m.get_class_name() + "->" + m.get_name()
                except Exception:
                    m_name = str(method)
                    
                unique_nodes.add(m_name)

                try:
                    for _, callee, _ in method.get_xref_to():
                        try:
                            cm = callee.get_method()
                            c_name = cm.get_class_name() + "->" + cm.get_name()
                        except Exception:
                            c_name = str(callee)
                        
                        unique_nodes.add(c_name)
                        unique_edges.add((m_name, c_name))

                        # Fast check using tuples instead of list iteration
                        if c_name.startswith(("Ljava/lang/", "Ljava/util/", "Ljava/io/", "Ljava/net/", "Landroidx/", "Lkotlin/")):
                            continue
                        
                        in_degrees[c_name] += 1
                        
                        for pat in SUSPICIOUS_API_PATTERNS:
                            if pat in c_name:
                                suspicious_api_hits.add(c_name)
                                break # Move to next c_name once flagged
                except Exception:
                    continue
                    
        suspicious_api_count = len(
            suspicious_api_hits
        )

        api_suspicion_score = min(
            100.0,
            suspicious_api_count * 8.0
        )
        
        top_apis = [k for k, v in in_degrees.most_common(10)]
        
        graph_node_count = len(unique_nodes)
        graph_edge_count = len(unique_edges)

        if graph_node_count > 1:
            graph_density = graph_edge_count / (graph_node_count * (graph_node_count - 1))
        else:
            graph_density = 0.0
        
        strings = []
        if analysis:
            strings = [s.get_value() for s in analysis.get_strings() if type(s.get_value()) == str]
        
        high_entropy_strings = [
            s for s in strings 
            if 20 < len(s) < 10000 and shannon_entropy(s) > 4.5
        ]
        high_entropy_count = len(high_entropy_strings)
            
        
        suspicious_urls = []
        for s in strings:
            if type(s) != str:
                continue

            match = URL_PATTERN.search(s)

            if match:
                suspicious_urls.append(match.group(0))
        
        c2_hit_count = 0
        intel = self.intel

        vt_result = intel.query_virustotal_hash(
            apk_hash
        )

        vt_malicious_count = 0
        vt_suspicious_count = 0

        if vt_result:
            try:
                stats = vt_result["data"]["attributes"]["last_analysis_stats"]

                vt_malicious_count = stats.get(
                    "malicious",
                    0
                )

                vt_suspicious_count = stats.get(
                    "suspicious",
                    0
                )

            except Exception:
                pass

        for url in suspicious_urls:
            domain = extract_domain(url)

            if intel.is_malicious_domain(domain):
                c2_hit_count += 1

        
        for s in strings:
            if type(s) != str: continue
            if URL_PATTERN.search(s):
                suspicious_urls.append(s)
            if IP_PATTERN.search(s):
                pass
                
        # A multiplier of 100 means the score reaches 100 only when ~all strings
        # are high-entropy. The previous value of 200 caused legitimate apps to
        # hit 100 when just 0.5% of their strings were high-entropy.
        obfuscation_score = min(100.0, (high_entropy_count / max(len(strings), 1)) * 100.0)

        suspicious_urls = list(
            set(suspicious_urls)
        )
        
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
                        # androguard 3.x uses asn1crypto; access .native to get a Python datetime
                        not_before = cert_info.not_valid_before
                        not_after = cert_info.not_valid_after
                        # asn1crypto objects expose .native; plain datetimes work directly
                        nb = not_before.native if hasattr(not_before, 'native') else not_before
                        na = not_after.native if hasattr(not_after, 'native') else not_after
                        if nb is not None and na is not None:
                            # Normalize to offset-naive for safe subtraction
                            import datetime as _dt
                            if hasattr(nb, 'utcoffset') and nb.utcoffset() is not None:
                                nb = nb.replace(tzinfo=None)
                            if hasattr(na, 'utcoffset') and na.utcoffset() is not None:
                                na = na.replace(tzinfo=None)
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
            
        has_native_code = False
        native_risk_score = 0.0
        so_files = []
        try:
            files = apk.get_files()
            so_files = [f for f in files if f.endswith('.so')]
            has_native_code = len(so_files) > 0
            if has_native_code:
                native_risk_score = 20.0
                for so in so_files:
                    filename = so.split('/')[-1]
                    if filename in KNOWN_MALICIOUS_LIBS:
                        native_risk_score += 30.0
                native_risk_score = min(100.0, native_risk_score)
        except Exception:
            pass

        anti_analysis_result = self.anti_analysis.analyze(
            decompiled_code=decompiled_code,
            extracted_strings=strings 
        )
        
        # We pass the raw APK path so it can inspect the ZIP headers
        resource_result = self.resource_analyzer.analyze(
            apk_path=apk_path
        )

        crypto_result = self.crypto_analyzer.analyze(
            decompiled_code,
            strings
        )

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
                {
                    "filename": f.filename, 
                    "reason": f.reason, 
                    "entropy": f.entropy
                } for f in resource_result.suspicious_files
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
