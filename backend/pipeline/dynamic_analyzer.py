import os
import time
import subprocess
from dataclasses import dataclass
from typing import List, Dict, Any

@dataclass
class DynamicFeatures:
    sandbox_mode: str                  # "live" or "emulated"
    sms_send_attempts: int
    network_domains_contacted: List[str]
    c2_domains_hit: int
    data_exfil_bytes: int
    accessibility_service_abused: bool
    clipboard_hijack_detected: bool
    silent_install_attempted: bool
    camera_accessed: bool
    microphone_accessed: bool
    location_accessed: bool
    device_admin_requested: bool
    behavioural_anomaly_score: float   # 0-100
    matched_malware_family: str        # e.g. "BankBot", "Unknown"
    family_similarity_score: float     # 0.0-1.0
    analysis_duration_ms: int

class SandboxError(Exception):
    pass

class DynamicAnalyzer:
    def __init__(self, use_live_sandbox: bool = False):
        self.use_live_sandbox = use_live_sandbox
        if self.use_live_sandbox:
            if not self._check_prerequisites():
                print("Warning: Live sandbox prerequisites missing. Falling back to Emulated Mode.")
                self.use_live_sandbox = False

    def _check_prerequisites(self) -> bool:
        try:
            # Check for adb devices
            res = subprocess.run(['adb', 'devices'], capture_output=True, text=True, timeout=5)
            if 'device\n' not in res.stdout and 'device\r\n' not in res.stdout:
                return False
            # We would normally also check for frida-server and mitmproxy here
            return True
        except Exception:
            return False

    def analyze(self, apk_path: str, package_name: str, timeout: int = 90) -> DynamicFeatures:
        t0 = time.time()
        
        if self.use_live_sandbox:
            features = self._run_live_sandbox(apk_path, package_name, timeout)
        else:
            features = self._run_emulated_sandbox(apk_path, package_name)
            
        features.analysis_duration_ms = int((time.time() - t0) * 1000)
        return features

    def _run_live_sandbox(self, apk_path: str, package_name: str, timeout: int) -> DynamicFeatures:
        # 1. INSTALL
        try:
            subprocess.run(['adb', 'install', '-r', apk_path], check=True, timeout=30)
        except Exception as e:
            raise SandboxError(f"Failed to install APK on sandbox: {str(e)}")

        # 2. START CAPTURE
        # mitm_proc = subprocess.Popen(['mitmdump', '-w', 'capture_file'])
        # session = frida.get_usb_device().attach(package_name)
        # script = session.create_script(frida_script)
        # script.on('message', on_message_handler)
        # script.load()
        
        # 3. LAUNCH + INTERACT
        try:
            subprocess.run(['adb', 'shell', 'monkey', '-p', package_name, '-v', '500'], timeout=timeout)
            time.sleep(10) # Simulate interaction time
        except subprocess.TimeoutExpired:
            pass # Expected
            
        # 4. COLLECT SIGNALS
        # Extract from mitmdump, frida events, and logcat
        
        # 5. UNINSTALL + RESET
        subprocess.run(['adb', 'uninstall', package_name], capture_output=True)
        # kill mitmproxy
        
        # Return dummy data for live mode as we aren't fully running mitm/frida here
        return DynamicFeatures(
            sandbox_mode="live",
            sms_send_attempts=0,
            network_domains_contacted=[],
            c2_domains_hit=0,
            data_exfil_bytes=0,
            accessibility_service_abused=False,
            clipboard_hijack_detected=False,
            silent_install_attempted=False,
            camera_accessed=False,
            microphone_accessed=False,
            location_accessed=False,
            device_admin_requested=False,
            behavioural_anomaly_score=10.0,
            matched_malware_family="Unknown",
            family_similarity_score=0.1,
            analysis_duration_ms=0
        )

    def _run_emulated_sandbox(self, apk_path: str, package_name: str) -> DynamicFeatures:
        # Emulated mode — no live device available.
        # Without a real sandbox (ADB + Frida + mitmproxy) we cannot observe actual
        # runtime behaviour, so we return conservative neutral values rather than
        # fabricating signals that would unfairly penalise legitimate apps.
        # The static analysis and ML scorer carry the weight in this mode.
        return DynamicFeatures(
            sandbox_mode="emulated",
            sms_send_attempts=0,
            network_domains_contacted=[],
            c2_domains_hit=0,
            data_exfil_bytes=0,
            accessibility_service_abused=False,
            clipboard_hijack_detected=False,
            silent_install_attempted=False,
            camera_accessed=False,
            microphone_accessed=False,
            location_accessed=False,
            device_admin_requested=False,
            behavioural_anomaly_score=0.0,
            matched_malware_family="Unknown",
            family_similarity_score=0.0,
            analysis_duration_ms=0  # Populated in analyze()
        )

if __name__ == "__main__":
    analyzer = DynamicAnalyzer()
    res = analyzer.analyze("test.apk", "com.example.app")
    import pprint
    pprint.pprint(res)
