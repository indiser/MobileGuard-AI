"""
MobileGuard AI — Runtime Collectors
Collect behavioural evidence from a sandboxed Android device via ADB
during APK dynamic analysis. All collectors are defensive: timeouts,
returncode checks, and per-collector error isolation are mandatory.

Architecture:
  DumpsysCollector   — system service state snapshots
  LogcatCollector    — real-time log event parsing
  NetworkCollector   — active connection enumeration
  ProcessCollector   — running process and package inspection
  CollectorOrchestrator — runs all collectors, aggregates results

Usage:
    orchestrator = CollectorOrchestrator(package="com.evil.apk", device_id="emulator-5554")
    result = orchestrator.collect_all(timeout_per_collector=15)
    all_events = result.events     # List[BehaviorEvent]
    errors     = result.errors     # List[str] — collector failures
"""

from __future__ import annotations

import logging
import re
import subprocess
import time
from dataclasses import dataclass, field
from typing import Optional

from backend.pipeline.runtime_events import (
    BehaviorEvent,
    CollectorResult,
    EventType,
    Severity,
)

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────
# ADB helper
# ─────────────────────────────────────────────────────────────────

# Default timeout for any single ADB call.
# Override per-call where longer output is expected (e.g. logcat).
ADB_DEFAULT_TIMEOUT = 10  # seconds

# Known C2 / malware IP ranges and domains (extend from threat_intel.py)
# These are loaded at runtime from config; this is the fallback set.
_KNOWN_C2_IPS: frozenset[str] = frozenset({
    "45.33.49.211", "185.220.101.0", "91.108.4.0",
    "194.165.16.0", "23.106.160.0",
})

_BANKING_PACKAGES: frozenset[str] = frozenset({
    "com.boi.mobile", "com.sbi.SBIFreedomPlus",
    "com.hdfc.mbanking", "com.axis.mobile",
    "com.icici.appathon.prod", "net.one97.paytm",
    "com.phonepe.app", "com.google.android.apps.nbu.paisa.user",
})


def _adb(
    args: list[str],
    device_id: str,
    timeout: int = ADB_DEFAULT_TIMEOUT,
) -> tuple[int, str, str]:
    """
    Run an adb command and return (returncode, stdout, stderr).
    Never raises — caller checks returncode.
    """
    cmd = ["adb", "-s", device_id] + args
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired:
        logger.warning("ADB timeout after %ds: %s", timeout, " ".join(cmd))
        return -1, "", f"timeout after {timeout}s"
    except FileNotFoundError:
        logger.error("adb not found in PATH — is Android SDK installed?")
        return -2, "", "adb binary not found"
    except Exception as e:
        logger.error("ADB unexpected error: %s", e)
        return -3, "", str(e)


# ─────────────────────────────────────────────────────────────────
# Base collector
# ─────────────────────────────────────────────────────────────────

class BaseCollector:
    """
    Common interface for all collectors.
    Subclasses implement _collect() and return List[BehaviorEvent].
    collect() wraps _collect() with timing and error isolation.
    """

    name: str = "base"

    def __init__(self, package: str, device_id: str):
        self.package   = package
        self.device_id = device_id

    def collect(self, timeout: int = ADB_DEFAULT_TIMEOUT) -> CollectorResult:
        t0 = time.time()
        try:
            events = self._collect(timeout=timeout)
            return CollectorResult(
                collector_name=self.name,
                events=events,
                duration_ms=int((time.time() - t0) * 1000),
            )
        except Exception as e:
            msg = f"{self.name} failed: {type(e).__name__}: {e}"
            logger.exception("Collector %s raised unexpectedly", self.name)
            return CollectorResult(
                collector_name=self.name,
                events=[BehaviorEvent(
                    event_type   = EventType.COLLECTOR_ERROR,
                    severity     = Severity.INFO,
                    source       = self.name,
                    raw_evidence = msg,
                    details      = {"exception": str(e)},
                    confidence   = 1.0,
                )],
                error=msg,
                duration_ms=int((time.time() - t0) * 1000),
            )

    def _collect(self, timeout: int) -> list[BehaviorEvent]:
        raise NotImplementedError


# ─────────────────────────────────────────────────────────────────
# 1. Dumpsys collector — system service state snapshots
# ─────────────────────────────────────────────────────────────────

class DumpsysCollector(BaseCollector):
    """
    Query Android system services via `dumpsys` to detect:
      - Accessibility services enabled by the APK under test
      - Device administrator activation
      - Overlay windows drawn over other apps
      - Active foreground package (detects when malware watches banking apps)
    """

    name = "dumpsys"

    def _collect(self, timeout: int) -> list[BehaviorEvent]:
        events: list[BehaviorEvent] = []
        events.extend(self._accessibility(timeout))
        events.extend(self._device_admin(timeout))
        events.extend(self._overlay_windows(timeout))
        events.extend(self._foreground_app(timeout))
        return events

    # ── Accessibility ─────────────────────────────────────────────

    def _accessibility(self, timeout: int) -> list[BehaviorEvent]:
        rc, stdout, stderr = _adb(
            ["shell", "dumpsys", "accessibility"], self.device_id, timeout
        )
        if rc != 0:
            return [self._adb_error("accessibility", stderr or stdout)]

        events: list[BehaviorEvent] = []

        # Extract enabled service components
        # Format: "enabledServices=com.evil/.EvilService"
        enabled_pattern = re.compile(
            r"(?:enabledServices|enabled services)\s*[=:]\s*([^\n]+)", re.IGNORECASE
        )
        for match in enabled_pattern.finditer(stdout):
            services_raw = match.group(1).strip()
            if not services_raw or services_raw in ("null", "[]", ""):
                continue

            for service in re.split(r"[,;]", services_raw):
                service = service.strip()
                if not service:
                    continue

                # Flag if the service belongs to our target package
                is_target = self.package and self.package in service
                # Flag any non-system service as suspicious
                is_system  = service.startswith("com.android.") or \
                              service.startswith("com.google.")

                if is_target or not is_system:
                    events.append(BehaviorEvent(
                        event_type      = EventType.ACCESSIBILITY_SERVICE_ENABLED,
                        severity        = Severity.CRITICAL if is_target else Severity.HIGH,
                        source          = self.name,
                        package         = self.package if is_target else service.split("/")[0],
                        raw_evidence    = match.group(0),
                        details         = {
                            "service_component":           service,
                            "belongs_to_target_package":   is_target,
                        },
                        confidence      = 1.0 if is_target else 0.7,
                        mitre_technique = "T1417.001",
                    ))

        return events

    # ── Device admin ──────────────────────────────────────────────

    def _device_admin(self, timeout: int) -> list[BehaviorEvent]:
        rc, stdout, stderr = _adb(
            ["shell", "dumpsys", "device_policy"], self.device_id, timeout
        )
        if rc != 0:
            return [self._adb_error("device_policy", stderr or stdout)]

        events: list[BehaviorEvent] = []

        # Extract active admin components
        # Format: "Admin: ComponentInfo{com.evil/com.evil.AdminReceiver}"
        admin_pattern = re.compile(
            r"Admin:\s*ComponentInfo\{([^}]+)\}", re.IGNORECASE
        )
        for match in admin_pattern.finditer(stdout):
            component = match.group(1).strip()
            pkg = component.split("/")[0]

            is_target = self.package and self.package in component
            is_system = pkg.startswith("com.android.") or pkg.startswith("com.google.")

            if is_target or not is_system:
                # Extract policies granted to this admin
                policies: list[str] = re.findall(
                    r"(uses-policies|policies):\s*\[([^\]]+)\]",
                    stdout, re.IGNORECASE
                )
                policy_list = []
                for _, pol_str in policies:
                    policy_list.extend(p.strip() for p in pol_str.split(","))

                events.append(BehaviorEvent(
                    event_type      = EventType.DEVICE_ADMIN_ACTIVATED,
                    severity        = Severity.CRITICAL,
                    source          = self.name,
                    package         = pkg,
                    raw_evidence    = match.group(0),
                    details         = {
                        "admin_component":           component,
                        "belongs_to_target_package": is_target,
                        "policies_granted":          policy_list,
                    },
                    confidence      = 1.0,
                    mitre_technique = "T1629.003",
                ))

        return events

    # ── Overlay windows ───────────────────────────────────────────

    def _overlay_windows(self, timeout: int) -> list[BehaviorEvent]:
        rc, stdout, stderr = _adb(
            ["shell", "dumpsys", "window", "windows"], self.device_id, timeout
        )
        if rc != 0:
            return [self._adb_error("window_windows", stderr or stdout)]

        events: list[BehaviorEvent] = []

        # Detect TYPE_APPLICATION_OVERLAY or TYPE_PHONE windows
        overlay_pattern = re.compile(
            r"Window\{[^}]+\}\s+.*?(?:TYPE_APPLICATION_OVERLAY|TYPE_PHONE|TYPE_SYSTEM_ALERT)"
            r".*?(?:ownerPackage|packageName)[=:]?\s*([^\s,}]+)",
            re.IGNORECASE | re.DOTALL,
        )

        # Simpler fallback: find any overlay type line and nearby package
        overlay_type_pattern = re.compile(
            r"(TYPE_APPLICATION_OVERLAY|TYPE_PHONE|TYPE_SYSTEM_ALERT)", re.IGNORECASE
        )
        package_near_pattern = re.compile(r"mOwnerUid=\d+\s+mShowingUid=\d+\s+(\S+)")

        for match in overlay_type_pattern.finditer(stdout):
            # Grab surrounding context (200 chars) to find package name
            start = max(0, match.start() - 200)
            end   = min(len(stdout), match.end() + 200)
            context = stdout[start:end]

            pkg_match = re.search(r"(?:ownerPackage|packageName)[=:\s]+([a-z][a-z0-9_.]+)", context)
            pkg = pkg_match.group(1) if pkg_match else "unknown"

            is_target  = self.package and self.package in context
            is_banking = any(b in context for b in _BANKING_PACKAGES)

            events.append(BehaviorEvent(
                event_type      = EventType.OVERLAY_WINDOW_DRAWN,
                severity        = Severity.CRITICAL if (is_target or is_banking) else Severity.HIGH,
                source          = self.name,
                package         = pkg,
                raw_evidence    = context.strip()[:300],
                details         = {
                    "window_type":               match.group(1),
                    "belongs_to_target_package": is_target,
                    "banking_app_targeted":      is_banking,
                },
                confidence      = 0.9,
                mitre_technique = "T1411",
            ))

        return events

    # ── Foreground app (banking app watch detection) ───────────────

    def _foreground_app(self, timeout: int) -> list[BehaviorEvent]:
        rc, stdout, stderr = _adb(
            ["shell", "dumpsys", "activity", "activities"], self.device_id, timeout
        )
        if rc != 0:
            return []  # non-critical, skip silently

        events: list[BehaviorEvent] = []

        # Detect if a known banking app is in the foreground
        fg_pattern = re.compile(r"mResumedActivity.*?([a-z][a-z0-9_.]+)/", re.IGNORECASE)
        for match in fg_pattern.finditer(stdout):
            fg_pkg = match.group(1)
            if fg_pkg in _BANKING_PACKAGES:
                events.append(BehaviorEvent(
                    event_type      = EventType.FOREGROUND_APP_CHANGED,
                    severity        = Severity.HIGH,
                    source          = self.name,
                    package         = fg_pkg,
                    raw_evidence    = match.group(0),
                    details         = {
                        "foreground_package": fg_pkg,
                        "is_banking_app":     True,
                        "note": "Malware may trigger overlay or credential harvest now.",
                    },
                    confidence      = 0.8,
                    mitre_technique = "T1411",
                ))

        return events

    # ── Error helper ──────────────────────────────────────────────

    def _adb_error(self, service: str, stderr: str) -> BehaviorEvent:
        return BehaviorEvent(
            event_type   = EventType.ADB_UNAVAILABLE,
            severity     = Severity.INFO,
            source       = self.name,
            raw_evidence = f"dumpsys {service} failed: {stderr[:200]}",
            details      = {"service": service},
            confidence   = 1.0,
        )


# ─────────────────────────────────────────────────────────────────
# 2. Logcat collector — real-time log parsing
# ─────────────────────────────────────────────────────────────────

class LogcatCollector(BaseCollector):
    """
    Parse buffered logcat output for security-relevant events:
      - SMS sending and receiving
      - Shell command execution
      - Dynamic code loading
      - Root/su attempts
      - Camera and microphone access
      - Clipboard access
      - Silent package installation
    """

    name = "logcat"

    # Logcat patterns: (compiled_regex, EventType, Severity, MITRE, confidence)
    _PATTERNS: list[tuple] = [
        (
            re.compile(r"SmsManager.*?sendTextMessage|sendMultipartTextMessage", re.IGNORECASE),
            EventType.SMS_SENT, Severity.CRITICAL, "T1582", 0.9,
        ),
        (
            re.compile(r"SMS_RECEIVED|SmsReceiver|getMessageBody", re.IGNORECASE),
            EventType.SMS_INTERCEPTED, Severity.CRITICAL, "T1636.004", 0.85,
        ),
        (
            re.compile(r"abortBroadcast.*SMS|SMS.*abortBroadcast", re.IGNORECASE),
            EventType.SMS_BROADCAST_ABORTED, Severity.CRITICAL, "T1636.004", 0.95,
        ),
        (
            re.compile(r"DexClassLoader|PathClassLoader.*(/sdcard|/data/local|getCacheDir)", re.IGNORECASE),
            EventType.DYNAMIC_CODE_LOADED, Severity.HIGH, "T1407", 0.85,
        ),
        (
            re.compile(r"Runtime\.exec|ProcessBuilder.*start|/system/bin/sh", re.IGNORECASE),
            EventType.SHELL_COMMAND_EXECUTED, Severity.HIGH, "T1623", 0.8,
        ),
        (
            re.compile(r"\bsu\b.*(-c|shell)|running as root|uid=0", re.IGNORECASE),
            EventType.ROOT_ATTEMPT, Severity.CRITICAL, "T1404", 0.9,
        ),
        (
            re.compile(r"Camera\.open|CameraDevice|openCamera", re.IGNORECASE),
            EventType.CAMERA_ACCESSED, Severity.HIGH, "T1512", 0.85,
        ),
        (
            re.compile(r"AudioRecord|MediaRecorder.*start|startRecording", re.IGNORECASE),
            EventType.MICROPHONE_ACCESSED, Severity.HIGH, "T1429", 0.85,
        ),
        (
            re.compile(r"getLastKnownLocation|requestLocationUpdates|FusedLocation", re.IGNORECASE),
            EventType.LOCATION_ACCESSED, Severity.HIGH, "T1430", 0.8,
        ),
        (
            re.compile(r"ClipboardManager|setPrimaryClip|getPrimaryClip", re.IGNORECASE),
            EventType.CLIPBOARD_READ, Severity.HIGH, "T1414", 0.8,
        ),
        (
            re.compile(r"PackageInstaller.*commit|installPackage|INSTALL_SUCCEEDED", re.IGNORECASE),
            EventType.PACKAGE_INSTALLED_SILENTLY, Severity.CRITICAL, "T1407", 0.9,
        ),
        (
            re.compile(r"setComponentEnabledSetting.*DISABLED|COMPONENT_ENABLED_STATE_DISABLED", re.IGNORECASE),
            EventType.ICON_HIDDEN, Severity.HIGH, "T1630.001", 0.9,
        ),
    ]

    def _collect(self, timeout: int) -> list[BehaviorEvent]:
        # Dump buffered logcat for the target package only
        # -d = dump and exit, -v time = include timestamps
        rc, stdout, stderr = _adb(
            ["shell", "logcat", "-d", "-v", "time",
             "--pid", self._get_pid() or "0"],
            self.device_id,
            timeout=max(timeout, 15),
        )

        if rc != 0 or not stdout.strip():
            # Fall back to full logcat filtered by package tag
            rc, stdout, stderr = _adb(
                ["shell", "logcat", "-d", "-v", "time"],
                self.device_id,
                timeout=max(timeout, 15),
            )

        if rc != 0:
            return [BehaviorEvent(
                event_type   = EventType.ADB_UNAVAILABLE,
                severity     = Severity.INFO,
                source       = self.name,
                raw_evidence = f"logcat failed (rc={rc}): {stderr[:200]}",
                details      = {},
                confidence   = 1.0,
            )]

        return self._parse_logcat(stdout)

    def _parse_logcat(self, logcat_output: str) -> list[BehaviorEvent]:
        events: list[BehaviorEvent] = []
        seen: set[str] = set()  # deduplicate identical lines

        for line in logcat_output.splitlines():
            line = line.strip()
            if not line or line in seen:
                continue

            for pattern, event_type, severity, mitre, confidence in self._PATTERNS:
                if pattern.search(line):
                    # Deduplicate by (event_type, line content)
                    dedup_key = f"{event_type}:{line[:80]}"
                    if dedup_key in seen:
                        continue
                    seen.add(dedup_key)

                    # Try to extract SMS destination if SMS event
                    details: dict = {}
                    if event_type == EventType.SMS_SENT:
                        dest_match = re.search(r"\+?[0-9]{10,15}", line)
                        if dest_match:
                            details["destination"] = dest_match.group(0)

                    events.append(BehaviorEvent(
                        event_type      = event_type,
                        severity        = severity,
                        source          = self.name,
                        package         = self.package,
                        raw_evidence    = line[:400],
                        details         = details,
                        confidence      = confidence,
                        mitre_technique = mitre,
                    ))
                    break  # one event per line

        return events

    def _get_pid(self) -> Optional[str]:
        """Get PID of target package for logcat filtering."""
        if not self.package:
            return None
        rc, stdout, _ = _adb(
            ["shell", "pidof", self.package], self.device_id, timeout=5
        )
        pid = stdout.strip()
        return pid if rc == 0 and pid.isdigit() else None


# ─────────────────────────────────────────────────────────────────
# 3. Network collector — active connections and DNS
# ─────────────────────────────────────────────────────────────────

class NetworkCollector(BaseCollector):
    """
    Enumerate active network connections from the sandbox.
    Cross-references remote IPs against known C2 blocklist.
    """

    name = "network"

    def _collect(self, timeout: int) -> list[BehaviorEvent]:
        events: list[BehaviorEvent] = []
        events.extend(self._tcp_connections(timeout))
        events.extend(self._dns_cache(timeout))
        return events

    def _tcp_connections(self, timeout: int) -> list[BehaviorEvent]:
        rc, stdout, stderr = _adb(
            ["shell", "cat", "/proc/net/tcp6"], self.device_id, timeout
        )
        if rc != 0:
            rc, stdout, stderr = _adb(
                ["shell", "cat", "/proc/net/tcp"], self.device_id, timeout
            )
        if rc != 0:
            return []

        events: list[BehaviorEvent] = []

        for line in stdout.splitlines()[1:]:  # skip header
            parts = line.split()
            if len(parts) < 4:
                continue

            # /proc/net/tcp hex-encodes addresses
            try:
                remote_hex = parts[2]
                remote_ip, remote_port = self._decode_hex_addr(remote_hex)
                state_hex = parts[3]
                # State 01 = ESTABLISHED, 0A = LISTEN
                if state_hex != "01":
                    continue
            except Exception:
                continue

            is_c2 = remote_ip in _KNOWN_C2_IPS

            # Skip loopback and private ranges (not exfiltration)
            if remote_ip.startswith(("127.", "10.", "192.168.", "172.")):
                continue

            events.append(BehaviorEvent(
                event_type      = EventType.C2_CONNECTION if is_c2
                                  else EventType.SUSPICIOUS_DOMAIN_CONTACT,
                severity        = Severity.CRITICAL if is_c2 else Severity.MEDIUM,
                source          = self.name,
                package         = self.package,
                raw_evidence    = line.strip(),
                details         = {
                    "remote_ip":    remote_ip,
                    "remote_port":  remote_port,
                    "c2_blocklist_hit": is_c2,
                    "state":        "ESTABLISHED",
                },
                confidence      = 1.0 if is_c2 else 0.6,
                mitre_technique = "T1437" if is_c2 else "T1437",
            ))

        return events

    def _dns_cache(self, timeout: int) -> list[BehaviorEvent]:
        """Check recent DNS lookups via nslookup/getprop — lightweight signal."""
        rc, stdout, _ = _adb(
            ["shell", "getprop", "net.dns1"], self.device_id, timeout=5
        )
        # This is informational only — just log the DNS server in use
        return []  # Extend with mitmproxy integration for full DNS capture

    @staticmethod
    def _decode_hex_addr(hex_addr: str) -> tuple[str, int]:
        """Decode /proc/net/tcp hex address:port to IP:port."""
        addr, port_hex = hex_addr.split(":")
        port = int(port_hex, 16)
        # IPv4 in /proc/net/tcp is little-endian hex
        if len(addr) == 8:
            ip = ".".join(str(int(addr[i:i+2], 16)) for i in (6, 4, 2, 0))
        else:
            # IPv6 — simplified, return raw for now
            ip = addr
        return ip, port


# ─────────────────────────────────────────────────────────────────
# 4. Process collector — running processes and packages
# ─────────────────────────────────────────────────────────────────

class ProcessCollector(BaseCollector):
    """
    Enumerate running processes and installed packages
    to detect dropper activity and silent installations.
    """

    name = "process"

    def _collect(self, timeout: int) -> list[BehaviorEvent]:
        events: list[BehaviorEvent] = []
        events.extend(self._running_processes(timeout))
        return events

    def _running_processes(self, timeout: int) -> list[BehaviorEvent]:
        rc, stdout, stderr = _adb(
            ["shell", "ps", "-A"], self.device_id, timeout
        )
        if rc != 0:
            return []

        events: list[BehaviorEvent] = []
        suspicious_cmds = ["su", "sh", "busybox", "magisk", "adbd"]

        for line in stdout.splitlines():
            parts = line.split()
            if len(parts) < 9:
                continue
            cmd = parts[-1]

            if any(s in cmd for s in suspicious_cmds):
                events.append(BehaviorEvent(
                    event_type      = EventType.SHELL_COMMAND_EXECUTED,
                    severity        = Severity.HIGH,
                    source          = self.name,
                    package         = self.package,
                    raw_evidence    = line.strip(),
                    details         = {
                        "process_name": cmd,
                        "is_root_tool": cmd in ("su", "magisk"),
                    },
                    confidence      = 0.7,
                    mitre_technique = "T1404",
                ))

        return events


# ─────────────────────────────────────────────────────────────────
# Orchestrator
# ─────────────────────────────────────────────────────────────────

@dataclass
class OrchestratorResult:
    events:          list[BehaviorEvent]
    collector_results: list[CollectorResult]
    errors:          list[str]
    total_duration_ms: int

    @property
    def succeeded(self) -> bool:
        return not self.errors


class CollectorOrchestrator:
    """
    Run all collectors against the sandboxed device and aggregate results.
    Each collector runs independently — one failure does not abort others.
    """

    def __init__(self, package: str, device_id: str = "emulator-5554"):
        self.package   = package
        self.device_id = device_id
        self._collectors = [
            DumpsysCollector(package, device_id),
            LogcatCollector(package, device_id),
            NetworkCollector(package, device_id),
            ProcessCollector(package, device_id),
        ]

    def collect_all(self, timeout_per_collector: int = 15) -> OrchestratorResult:
        """
        Run every collector with per-collector error isolation.
        Returns all events and all errors regardless of partial failures.
        """
        t0 = time.time()
        all_events:   list[BehaviorEvent]   = []
        all_results:  list[CollectorResult] = []
        all_errors:   list[str]             = []

        for collector in self._collectors:
            logger.info("Running collector: %s", collector.name)
            result = collector.collect(timeout=timeout_per_collector)
            all_results.append(result)
            all_events.extend(result.events)
            if result.error:
                all_errors.append(f"[{collector.name}] {result.error}")
                logger.warning("Collector %s failed: %s", collector.name, result.error)
            else:
                logger.info(
                    "Collector %s: %d events in %dms",
                    collector.name, len(result.events), result.duration_ms
                )

        return OrchestratorResult(
            events            = all_events,
            collector_results = all_results,
            errors            = all_errors,
            total_duration_ms = int((time.time() - t0) * 1000),
        )