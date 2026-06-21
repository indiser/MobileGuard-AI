"""
dynamic_analyzer.py
--------------------
Runs an APK through a live (ADB + Frida + mitmproxy) or emulated sandbox and
returns a structured DynamicFeatures report.

Live mode requires:
  - adb in PATH, a connected/authorised device or emulator
  - frida-server running on the device  (optional but enriches output)
  - mitmdump in PATH                    (optional but enriches output)
"""

import logging
import os
import re
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from backend.pipeline.behavior_scorer import score_behavior

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class DynamicFeatures:
    sandbox_mode: str                       # "live" | "emulated"
    sms_send_attempts: int
    network_domains_contacted: list[str]
    c2_domains_hit: int
    data_exfil_bytes: int
    accessibility_service_abused: bool
    clipboard_hijack_detected: bool
    silent_install_attempted: bool
    camera_accessed: bool
    microphone_accessed: bool
    location_accessed: bool
    device_admin_requested: bool
    overlay_detected: bool
    behavioural_anomaly_score: float        # 0–100
    matched_malware_family: str             # e.g. "BankBot", "Unknown"
    family_similarity_score: float          # 0.0–1.0
    analysis_duration_ms: int


@dataclass
class LogcatSignals:
    """Parsed signals extracted from a logcat capture."""
    sms_attempts: int = 0
    domains: list[str] = field(default_factory=list)
    accessibility: bool = False
    device_admin: bool = False
    clipboard: bool = False
    camera: bool = False
    microphone: bool = False
    location: bool = False
    silent_install: bool = False


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class SandboxError(Exception):
    """Raised when the sandbox environment cannot be set up or used."""


class PrerequisiteError(SandboxError):
    """Raised when a required external tool is missing or not reachable."""


# ---------------------------------------------------------------------------
# Logcat parser
# ---------------------------------------------------------------------------

# Compiled once at import time for efficiency.
_DOMAIN_RE = re.compile(r"https?://([A-Za-z0-9.\-]+)")


def parse_logcat(logs: str) -> LogcatSignals:
    """
    Parse a raw logcat string and return a :class:`LogcatSignals` instance.

    Notes
    -----
    - Boolean flags start as ``False`` and are set to ``True`` on first match;
      they never revert, so variable-before-assignment bugs are impossible.
    - Domain extraction uses a regex on the URL portion rather than appending
      the whole log line, which previously caused noisy / non-domain values.
    - The domain list is deduplicated while preserving first-seen order.
    """
    signals = LogcatSignals()
    seen_domains: dict[str, None] = {}  # ordered-set idiom

    for line in logs.splitlines():
        if "SmsManager" in line:
            signals.sms_attempts += 1

        if "AccessibilityService" in line:
            signals.accessibility = True

        if "DevicePolicyManager" in line:
            signals.device_admin = True

        if "ClipboardManager" in line:
            signals.clipboard = True

        if "CameraManager" in line:
            signals.camera = True

        if "MediaRecorder" in line:
            signals.microphone = True

        if "LocationManager" in line:
            signals.location = True

        if "PackageInstaller" in line:
            signals.silent_install = True

        for domain in _DOMAIN_RE.findall(line):
            seen_domains[domain] = None

    signals.domains = list(seen_domains)
    return signals


# ---------------------------------------------------------------------------
# Prerequisite checks
# ---------------------------------------------------------------------------

def _require_tool(name: str, test_args: list[str], timeout: int = 5) -> None:
    """
    Assert that an external tool is available and responds successfully.

    Raises :class:`PrerequisiteError` if the tool cannot be found or times out.
    """
    try:
        subprocess.run(
            test_args,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=True,
        )
    except FileNotFoundError:
        raise PrerequisiteError(f"'{name}' not found in PATH.")
    except subprocess.TimeoutExpired:
        raise PrerequisiteError(f"'{name}' timed out during prerequisite check.")
    except subprocess.CalledProcessError as exc:
        raise PrerequisiteError(f"'{name}' returned non-zero exit: {exc.returncode}.")


def _check_adb_device() -> bool:
    """Return True if at least one authorised ADB device/emulator is connected."""
    try:
        result = subprocess.run(
            ["adb", "devices"],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except Exception:
        return False

    # Each connected device appears as "<serial>  device" (tab-separated).
    # Lines ending in "offline" or "unauthorized" do not count.
    return any(
        line.endswith("\tdevice") or line.endswith(" device")
        for line in result.stdout.splitlines()[1:]  # skip header line
        if line.strip()
    )


# ---------------------------------------------------------------------------
# Main analyser
# ---------------------------------------------------------------------------

class DynamicAnalyzer:
    """
    Orchestrates dynamic analysis of an Android APK.

    Parameters
    ----------
    use_live_sandbox:
        If ``True``, attempt to use a connected ADB device/emulator with
        Frida and mitmproxy.  Falls back to emulated mode automatically when
        prerequisites are missing.
    monkey_event_count:
        Number of pseudo-random UI events sent via ``adb shell monkey``.
    interaction_timeout:
        Seconds to let the app run before collection is stopped.
    """

    def __init__(
        self,
        use_live_sandbox: bool = True,
        monkey_event_count: int = 500,
        interaction_timeout: int = 90,
    ) -> None:
        self.monkey_event_count = monkey_event_count
        self.interaction_timeout = interaction_timeout
        

        if use_live_sandbox:
            if _check_adb_device():
                self.use_live_sandbox = True
                log.info("Live sandbox mode enabled.")
            else:
                log.warning(
                    "No authorised ADB device found. Falling back to emulated mode."
                )
                self.use_live_sandbox = False
        else:
            self.use_live_sandbox = False

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze(
        self,
        apk_path: str | os.PathLike,
        package_name: str,
    ) -> DynamicFeatures:
        """
        Run the APK through the sandbox and return a :class:`DynamicFeatures`
        report.

        Parameters
        ----------
        apk_path:
            Path to the APK file on the local filesystem.
        package_name:
            Android package identifier (e.g. ``com.example.app``).

        Raises
        ------
        FileNotFoundError
            If ``apk_path`` does not exist.
        SandboxError
            If live-mode setup fails unrecoverably.
        """
        apk_path = Path(apk_path)
        if not apk_path.exists():
            raise FileNotFoundError(f"APK not found: {apk_path}")

        t0 = time.monotonic()

        if self.use_live_sandbox:
            features = self._run_live_sandbox(apk_path, package_name)
        else:
            features = self._run_emulated_sandbox(apk_path, package_name)

        features.analysis_duration_ms = int((time.monotonic() - t0) * 1000)
        log.info(
            "Analysis complete in %d ms (mode=%s, family=%s, score=%.1f)",
            features.analysis_duration_ms,
            features.sandbox_mode,
            features.matched_malware_family,
            features.behavioural_anomaly_score,
        )
        return features

    # ------------------------------------------------------------------
    # Live sandbox
    # ------------------------------------------------------------------

    def _run_live_sandbox(
        self,
        apk_path: Path,
        package_name: str,
    ) -> DynamicFeatures:
        self._install_apk(apk_path)
        logcat_proc = self._start_logcat()

        try:
            self._interact(package_name)
        finally:
            # Always stop logcat and uninstall, even if interaction raises.
            logcat_proc.terminate()
            stdout, _ = logcat_proc.communicate(timeout=10)
            self._uninstall_apk(package_name)

        signals = parse_logcat(stdout)

        runtime = self._collect_runtime_state(
            package_name
        )

        features = self._signals_to_features(
            signals,
            sandbox_mode="live"
        )
        features.behavioural_anomaly_score = score_behavior(features)
        features.accessibility_service_abused = (
            features.accessibility_service_abused
            or runtime["accessibility"]
        )

        features.device_admin_requested = (
            features.device_admin_requested
            or runtime["device_admin"]
        )

        return features

    def _install_apk(self, apk_path: Path) -> None:
        log.debug("Installing %s …", apk_path)
        try:
            subprocess.run(
                ["adb", "install", "-r", str(apk_path)],
                check=True,
                capture_output=True,
                timeout=30,
            )
        except subprocess.CalledProcessError as exc:
            raise SandboxError(
                f"APK installation failed (exit {exc.returncode}): "
                f"{exc.stderr.strip()}"
            ) from exc
        except subprocess.TimeoutExpired as exc:
            raise SandboxError("APK installation timed out.") from exc

    def _start_logcat(self) -> subprocess.Popen:
        """Start a background logcat process and return the handle."""
        log.debug("Starting logcat capture …")
        # Clear the buffer first so we only capture events from this run.
        subprocess.run(["adb", "logcat", "-c"], capture_output=True)
        return subprocess.Popen(
            ["adb", "logcat", "-v", "time"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )

    def _interact(self, package_name: str) -> None:
        """Launch the app and send pseudo-random UI events via monkey."""
        log.debug(
            "Running monkey (%d events, timeout=%ds) …",
            self.monkey_event_count,
            self.interaction_timeout,
        )
        try:
            subprocess.run(
                [
                    "adb", "shell", "monkey",
                    "-p", package_name,
                    "--throttle", "200",
                    "--ignore-crashes",
                    "--ignore-timeouts",
                    "-v", str(self.monkey_event_count),
                ],
                timeout=self.interaction_timeout,
                capture_output=True,
            )
        except subprocess.TimeoutExpired:
            log.debug("Monkey timed out — expected for long-running analysis.")

        # Brief settle time so async operations flush to logcat.
        time.sleep(5)

    def _uninstall_apk(self, package_name: str) -> None:
        log.debug("Uninstalling %s …", package_name)
        subprocess.run(
            ["adb", "uninstall", package_name],
            capture_output=True,
            timeout=15,
        )

    # ------------------------------------------------------------------
    # Emulated sandbox
    # ------------------------------------------------------------------

    def _run_emulated_sandbox(
        self,
        apk_path: Path,
        package_name: str,
    ) -> DynamicFeatures:
        """
        Emulated mode — no live device available.

        Without a real sandbox (ADB + Frida + mitmproxy) we cannot observe
        actual runtime behaviour, so we return conservative neutral values
        rather than fabricating signals that would unfairly penalise
        legitimate apps.  The static analysis and ML scorer carry the weight
        in this mode.
        """
        log.info("Emulated mode: returning neutral dynamic features for %s.", package_name)
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
            overlay_detected=False,
            behavioural_anomaly_score=0.0,
            matched_malware_family="Unknown",
            family_similarity_score=0.0,
            analysis_duration_ms=0,  # Overwritten in analyze()
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _signals_to_features(
        signals: LogcatSignals,
        sandbox_mode: str,
    ) -> DynamicFeatures:
        """Convert a :class:`LogcatSignals` into a :class:`DynamicFeatures`."""
        return DynamicFeatures(
            sandbox_mode=sandbox_mode,
            sms_send_attempts=signals.sms_attempts,
            network_domains_contacted=signals.domains,
            c2_domains_hit=0,           # Populated by C2 reputation feed (future)
            data_exfil_bytes=0,         # Populated by mitmproxy capture (future)
            accessibility_service_abused=signals.accessibility,
            clipboard_hijack_detected=signals.clipboard,
            silent_install_attempted=signals.silent_install,
            camera_accessed=signals.camera,
            microphone_accessed=signals.microphone,
            location_accessed=signals.location,
            device_admin_requested=signals.device_admin,
            overlay_detected=False,
            behavioural_anomaly_score=0.0,      # Set after scoring
            matched_malware_family="Unknown",   # Set by family classifier
            family_similarity_score=0.0,        # Set by family classifier
            analysis_duration_ms=0,             # Set in analyze()
        )
    
    def _collect_runtime_state(self, package_name: str):

        def run_cmd(cmd):
            try:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                return result.stdout
            except Exception:
                return ""

        accessibility_dump = run_cmd(
            [
                "adb",
                "shell",
                "dumpsys",
                "accessibility"
            ]
        )

        device_policy_dump = run_cmd(
            [
                "adb",
                "shell",
                "dumpsys",
                "device_policy"
            ]
        )

        services_dump = run_cmd(
            [
                "adb",
                "shell",
                "dumpsys",
                "activity",
                "services"
            ]
        )

        window_dump = run_cmd(
            [
                "adb",
                "shell",
                "dumpsys",
                "window"
            ]
        )

        accessibility_enabled = (
            package_name.lower()
            in accessibility_dump.lower()
        )

        device_admin = (
            package_name.lower()
            in device_policy_dump.lower()
        )

        overlay_detected = (
            "TYPE_APPLICATION_OVERLAY"
            in window_dump
        )

        foreground_services = services_dump.count(
            package_name
        )

        return {
            "accessibility": accessibility_enabled,
            "device_admin": device_admin,
            "overlay": overlay_detected,
            "services": foreground_services,
        }


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse
    import pprint

    logging.basicConfig(level=logging.INFO, format="%(levelname)s  %(message)s")

    parser = argparse.ArgumentParser(description="Run dynamic APK analysis.")
    parser.add_argument("apk", help="Path to the APK file.")
    parser.add_argument("package", help="Android package name (e.g. com.example.app).")
    parser.add_argument("--live", action="store_true", help="Use live ADB sandbox.")
    parser.add_argument("--events", type=int, default=500, help="Monkey event count.")
    parser.add_argument("--timeout", type=int, default=90, help="Interaction timeout (s).")
    args = parser.parse_args()

    analyzer = DynamicAnalyzer(
        use_live_sandbox=args.live,
        monkey_event_count=args.events,
        interaction_timeout=args.timeout,
    )
    result = analyzer.analyze(args.apk, args.package)
    pprint.pprint(result)