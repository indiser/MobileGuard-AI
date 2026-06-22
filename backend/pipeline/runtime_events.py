"""
MobileGuard AI — Runtime Event Model
Structured, validated event objects emitted by all runtime collectors.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

def _utc_now() -> str:
    return datetime.now(
        timezone.utc
    ).isoformat()


# ─────────────────────────────────────────────────────────────────
# Controlled vocabularies — no free-text severity or event types
# ─────────────────────────────────────────────────────────────────

class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"
    INFO     = "info"


class EventType(str, Enum):
    # Accessibility
    ACCESSIBILITY_SERVICE_ENABLED  = "accessibility_service_enabled"
    ACCESSIBILITY_NODE_READ        = "accessibility_node_read"

    # Device administration
    DEVICE_ADMIN_ACTIVATED         = "device_admin_activated"
    DEVICE_ADMIN_REQUESTED         = "device_admin_requested"

    # SMS
    SMS_SENT                       = "sms_sent"
    SMS_INTERCEPTED                = "sms_intercepted"
    SMS_BROADCAST_ABORTED          = "sms_broadcast_aborted"

    # Network
    C2_CONNECTION                  = "c2_connection"
    SUSPICIOUS_DOMAIN_CONTACT      = "suspicious_domain_contact"
    DATA_EXFILTRATION              = "data_exfiltration"
    CLEARTEXT_TRAFFIC              = "cleartext_traffic"

    # Overlay / UI
    OVERLAY_WINDOW_DRAWN           = "overlay_window_drawn"
    FOREGROUND_APP_CHANGED         = "foreground_app_changed"

    # Process / code execution
    SHELL_COMMAND_EXECUTED         = "shell_command_executed"
    DYNAMIC_CODE_LOADED            = "dynamic_code_loaded"
    PACKAGE_INSTALLED_SILENTLY     = "package_installed_silently"
    ROOT_ATTEMPT                   = "root_attempt"

    # Sensors / media
    CAMERA_ACCESSED                = "camera_accessed"
    MICROPHONE_ACCESSED            = "microphone_accessed"
    LOCATION_ACCESSED              = "location_accessed"
    CLIPBOARD_READ                 = "clipboard_read"

    # Persistence
    BOOT_RECEIVER_REGISTERED       = "boot_receiver_registered"
    ALARM_SCHEDULED                = "alarm_scheduled"
    ICON_HIDDEN                    = "icon_hidden"

    # Collector health
    COLLECTOR_ERROR                = "collector_error"
    COLLECTOR_TIMEOUT              = "collector_timeout"
    ADB_UNAVAILABLE                = "adb_unavailable"


# ─────────────────────────────────────────────────────────────────
# Core event dataclass
# ─────────────────────────────────────────────────────────────────

@dataclass
class BehaviorEvent:
    """
    A single observable runtime behaviour captured during APK sandboxing.

    Fields
    ------
    event_type      Controlled vocabulary — use EventType enum.
    severity        Controlled vocabulary — use Severity enum.
    source          Which collector produced this event (e.g. "dumpsys_accessibility").
    package         Android package name of the app that caused the event.
                    Empty string if unknown.
    timestamp       UTC ISO-8601. Auto-populated if not supplied.
    raw_evidence    The raw adb/dumpsys/logcat output line(s) that triggered
                    this event. Never empty — analysts need to verify findings.
    details         Structured key→value pairs specific to this event type.
                    Must be JSON-serialisable. See per-type conventions below.
    confidence      0.0–1.0. How certain we are this is a true positive.
                    1.0 = confirmed (e.g. raw SMS content captured).
                    0.5 = inferred from indirect signal.
    mitre_technique MITRE ATT&CK technique ID if applicable (e.g. "T1582").

    Per-EventType details conventions
    ----------------------------------
    SMS_SENT:
        {"destination": "+91XXXXXXXXXX", "message_preview": "...", "is_premium": bool}
    C2_CONNECTION:
        {"remote_ip": "x.x.x.x", "remote_port": int, "protocol": "tcp/udp",
         "bytes_sent": int, "blocklist_hit": bool}
    OVERLAY_WINDOW_DRAWN:
        {"target_package": "com.example.bank", "window_type": "TYPE_APPLICATION_OVERLAY"}
    SHELL_COMMAND_EXECUTED:
        {"command": "su -c ...", "is_root": bool}
    DEVICE_ADMIN_ACTIVATED:
        {"admin_component": "com.evil/AdminReceiver", "policies": [...]}
    ACCESSIBILITY_SERVICE_ENABLED:
        {"service_component": "com.evil/.AccessibilityService", "can_retrieve_window_content": bool}
    """
    event_type:      EventType
    severity:        Severity
    source:          str
    raw_evidence:    str                        # never empty in production
    package:         str          = ""
    timestamp:       str          = field(default_factory=_utc_now)
    details:         dict[str, Any] = field(default_factory=dict)
    confidence:      float        = 1.0         # 0.0–1.0
    mitre_technique: str          = ""

    def __post_init__(self) -> None:
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(f"confidence must be 0.0–1.0, got {self.confidence}")
        if not self.raw_evidence:
            # Enforce evidence — empty string is a code smell, not valid
            raise ValueError(
                f"raw_evidence must not be empty for event {self.event_type}. "
                "Store the adb output line or logcat entry that triggered this event."
            )


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ─────────────────────────────────────────────────────────────────
# Collector result wrapper
# ─────────────────────────────────────────────────────────────────

@dataclass
class CollectorResult:
    """
    Wraps the output of a single collector method.
    Separates clean events from collector-level errors so
    collect_all() can accumulate both without losing either.
    """
    collector_name: str
    events:         list[BehaviorEvent] = field(default_factory=list)
    error:          Optional[str]       = None    # None = success
    duration_ms:    int                 = 0

    @property
    def succeeded(self) -> bool:
        return self.error is None