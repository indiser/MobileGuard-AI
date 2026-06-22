"""
MobileGuard AI — Event Mapper
Maps a list of BehaviorEvents from the collector orchestrator
into DynamicFeatures fields in a single pass, with confidence
weighting and a mapping summary for the report generator.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from backend.pipeline.runtime_events import BehaviorEvent, EventType, Severity

logger = logging.getLogger(__name__)

# Minimum confidence threshold — events below this are logged but
# do not flip boolean flags or increment counters.
CONFIDENCE_THRESHOLD = 0.5


@dataclass
class MappingSummary:
    """
    Returned alongside the mutated features object.
    Used by report_generator.py to cite specific evidence
    rather than just asserting flags are set.
    """
    total_events:           int = 0
    events_below_threshold: int = 0          # low-confidence, not applied
    collector_errors:       int = 0
    critical_events:        list[str] = field(default_factory=list)   # raw_evidence strings
    high_events:            list[str] = field(default_factory=list)
    unique_c2_ips:          list[str] = field(default_factory=list)
    unique_domains:         list[str] = field(default_factory=list)
    sms_destinations:       list[str] = field(default_factory=list)
    root_commands:          list[str] = field(default_factory=list)
    dynamic_libs_loaded:    list[str] = field(default_factory=list)
    mapped_mitre_techniques: list[str] = field(default_factory=list)


class EventMapper:
    """
    Single-pass mapper from List[BehaviorEvent] → DynamicFeatures.

    Design rules:
    - One iteration over events, not one per field.
    - Confidence-weighted: events below CONFIDENCE_THRESHOLD are
      counted in summary but do not mutate features.
    - All new EventTypes from the improved collectors are covered.
    - Returns (features, MappingSummary) so callers have evidence
      for audit logs and report generation.
    """

    @staticmethod
    def apply(
        events: list[BehaviorEvent] | None,
        features: Any,
    ) -> tuple[Any, MappingSummary]:
        """
        Parameters
        ----------
        events   : list of BehaviorEvents from CollectorOrchestrator.
                   None or empty list is safe — returns zeroed features.
        features : DynamicFeatures dataclass instance to mutate in place.

        Returns
        -------
        (features, MappingSummary)
        """
        summary = MappingSummary()

        if not events:
            logger.warning("EventMapper received empty or None events list.")
            return features, summary

        # ── Initialise accumulators ───────────────────────────────
        sms_count           = 0
        c2_count            = 0
        data_exfil_bytes    = 0
        a11y_abused         = False
        device_admin        = False
        camera              = False
        microphone          = False
        location            = False
        clipboard           = False
        overlay             = False
        silent_install      = False
        root_detected       = False
        icon_hidden         = False
        dynamic_code_loaded = False
        shell_executed      = False

        unique_c2_ips:    set[str] = set()
        unique_domains:   set[str] = set()
        sms_destinations: set[str] = set()
        root_commands:    list[str] = []
        dynamic_libs:     list[str] = []
        mitre_techniques: set[str] = set()

        # ── Single pass ───────────────────────────────────────────
        for event in events:
            summary.total_events += 1

            # Track collector-level errors
            if event.event_type in (
                EventType.COLLECTOR_ERROR,
                EventType.COLLECTOR_TIMEOUT,
                EventType.ADB_UNAVAILABLE,
            ):
                summary.collector_errors += 1
                continue

            # Collect MITRE techniques seen
            if event.mitre_technique:
                mitre_techniques.add(event.mitre_technique)

            # Bucket critical and high events for the report
            if event.severity == Severity.CRITICAL:
                summary.critical_events.append(event.raw_evidence[:200])
            elif event.severity == Severity.HIGH:
                summary.high_events.append(event.raw_evidence[:200])

            # Low-confidence events are recorded in summary but do not
            # flip flags — prevents noisy logcat matches from inflating score
            if event.confidence < CONFIDENCE_THRESHOLD:
                summary.events_below_threshold += 1
                logger.debug(
                    "Skipping low-confidence event %s (%.2f): %s",
                    event.event_type, event.confidence, event.raw_evidence[:80]
                )
                continue

            # ── Map each EventType ────────────────────────────────

            if event.event_type == EventType.SMS_SENT:
                sms_count += 1
                dest = event.details.get("destination", "")
                if dest:
                    sms_destinations.add(dest)

            elif event.event_type == EventType.SMS_INTERCEPTED:
                # Interception without sending is still critical —
                # flag separately so scorer can weight it
                a11y_abused = True   # OTP interception = accessibility chain

            elif event.event_type == EventType.SMS_BROADCAST_ABORTED:
                # Suppressing SMS broadcast is definitive OTP theft
                sms_count += 1      # treat as an interception attempt

            elif event.event_type == EventType.ACCESSIBILITY_SERVICE_ENABLED:
                a11y_abused = True

            elif event.event_type == EventType.DEVICE_ADMIN_ACTIVATED:
                device_admin = True

            elif event.event_type == EventType.DEVICE_ADMIN_REQUESTED:
                device_admin = True   # requested but not yet granted — still flag

            elif event.event_type == EventType.CAMERA_ACCESSED:
                camera = True

            elif event.event_type == EventType.MICROPHONE_ACCESSED:
                microphone = True

            elif event.event_type == EventType.LOCATION_ACCESSED:
                location = True

            elif event.event_type == EventType.CLIPBOARD_READ:
                clipboard = True

            elif event.event_type == EventType.OVERLAY_WINDOW_DRAWN:
                overlay = True

            elif event.event_type == EventType.PACKAGE_INSTALLED_SILENTLY:
                silent_install = True

            elif event.event_type == EventType.ICON_HIDDEN:
                icon_hidden = True

            elif event.event_type == EventType.DYNAMIC_CODE_LOADED:
                dynamic_code_loaded = True
                lib = event.details.get("path", event.raw_evidence[:80])
                dynamic_libs.append(lib)

            elif event.event_type == EventType.SHELL_COMMAND_EXECUTED:
                shell_executed = True
                cmd = event.details.get("command", event.raw_evidence[:80])
                root_commands.append(cmd)

            elif event.event_type == EventType.ROOT_ATTEMPT:
                root_detected = True
                cmd = event.details.get("command", event.raw_evidence[:80])
                root_commands.append(cmd)

            elif event.event_type == EventType.C2_CONNECTION:
                c2_count += 1
                ip = event.details.get("remote_ip", "")
                if ip:
                    unique_c2_ips.add(ip)

            elif event.event_type == EventType.SUSPICIOUS_DOMAIN_CONTACT:
                domain = event.details.get("remote_ip",
                         event.details.get("domain", ""))
                if domain:
                    unique_domains.add(domain)

            elif event.event_type == EventType.DATA_EXFILTRATION:
                data_exfil_bytes += int(event.details.get("bytes_sent", 0))

        # ── Write to features ─────────────────────────────────────
        # Use getattr/setattr so this works even if DynamicFeatures
        # adds or removes fields without breaking the mapper.

        _set(features, "sms_send_attempts",          sms_count)
        _set(features, "accessibility_service_abused", a11y_abused)
        _set(features, "device_admin_requested",     device_admin)
        _set(features, "camera_accessed",            camera)
        _set(features, "microphone_accessed",        microphone)
        _set(features, "location_accessed",          location)
        _set(features, "clipboard_hijack_detected",  clipboard)
        _set(features, "overlay_detected",           overlay)
        _set(features, "c2_domains_hit",             c2_count)
        _set(features, "silent_install_attempted",   silent_install)
        _set(features, "root_detected",              root_detected)
        _set(features, "icon_hidden",                icon_hidden)
        _set(features, "dynamic_code_loaded",        dynamic_code_loaded)
        _set(features, "shell_executed",             shell_executed)
        _set(features, "data_exfil_bytes",           data_exfil_bytes)
        _set(features, "network_domains_contacted",  list(unique_domains))
        _set(features, "runtime_events",             events)

        # ── Populate summary ──────────────────────────────────────
        summary.unique_c2_ips          = sorted(unique_c2_ips)
        summary.unique_domains         = sorted(unique_domains)
        summary.sms_destinations       = sorted(sms_destinations)
        summary.root_commands          = root_commands[:10]       # cap list length
        summary.dynamic_libs_loaded    = dynamic_libs[:10]
        summary.mapped_mitre_techniques = sorted(mitre_techniques)

        logger.info(
            "EventMapper: %d events processed | %d below threshold | "
            "%d CRITICAL | %d HIGH | %d C2 hits | %d SMS attempts",
            summary.total_events,
            summary.events_below_threshold,
            len(summary.critical_events),
            len(summary.high_events),
            c2_count,
            sms_count,
        )

        return features, summary


# ── Helper ────────────────────────────────────────────────────────

def _set(obj: Any, attr: str, value: Any) -> None:
    """
    Set attribute on obj if it exists. Log a warning if the field
    is missing — means DynamicFeatures and EventMapper are out of sync.
    """
    if hasattr(obj, attr):
        setattr(obj, attr, value)
    else:
        logger.warning(
            "EventMapper: DynamicFeatures has no field '%s' — "
            "add it or remove from mapper.", attr
        )