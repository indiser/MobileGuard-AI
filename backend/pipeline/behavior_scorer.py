"""
behavior_scorer.py
------------------
Heuristic behavioural anomaly scorer for DynamicFeatures.

Returns a float in [0, 100].  Each signal contributes up to a declared
cap so that a single noisy signal (e.g. many SMS attempts) cannot
dominate the entire score.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from backend.pipeline.dynamic_analyzer import DynamicFeatures


# ---------------------------------------------------------------------------
# Signal definitions — edit weights here, not in logic below
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class _Signal:
    """A single scoring rule with an optional per-unit cap."""
    weight: float       # points per unit (or flat points for boolean signals)
    cap: float          # maximum contribution from this signal


_BOOLEAN_SIGNALS: dict[str, _Signal] = {
    "accessibility_service_abused": _Signal(weight=25.0, cap=25.0),
    "device_admin_requested":       _Signal(weight=20.0, cap=20.0),
    "silent_install_attempted":     _Signal(weight=20.0, cap=20.0),
    "clipboard_hijack_detected":    _Signal(weight=15.0, cap=15.0),
    "overlay_detected":             _Signal(weight=20.0, cap=20.0),
    "camera_accessed":              _Signal(weight=10.0, cap=10.0),
    "microphone_accessed":          _Signal(weight=10.0, cap=10.0),
    "location_accessed":            _Signal(weight=10.0, cap=10.0),
    # Fields added by the improved dynamic_analyzer / event_mapper:
    "root_detected":                _Signal(weight=30.0, cap=30.0),
    "shell_executed":               _Signal(weight=15.0, cap=15.0),
    "dynamic_code_loaded":          _Signal(weight=15.0, cap=15.0),
    "icon_hidden":                  _Signal(weight=10.0, cap=10.0),
}

_SCALED_SIGNALS: dict[str, _Signal] = {
    # 20 pts per SMS attempt, capped at 40 so 3 attempts != auto-100
    "sms_send_attempts":            _Signal(weight=20.0, cap=40.0),
    # 5 pts per contacted domain, capped at 25
    "network_domains_contacted":    _Signal(weight=5.0,  cap=25.0),
    # 10 pts per C2 hit, capped at 30
    "c2_domains_hit":               _Signal(weight=10.0, cap=30.0),
    # 1 pt per KB exfiltrated, capped at 20
    "data_exfil_bytes":             _Signal(weight=0.001, cap=20.0),
}

_SCORE_CEILING = 100.0


# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------

def score_behavior(features: "DynamicFeatures") -> float:
    """
    Compute a behavioural anomaly score for *features*.

    Parameters
    ----------
    features:
        A ``DynamicFeatures`` instance (or any object with matching attributes).

    Returns
    -------
    float
        A value in ``[0.0, 100.0]``.
    """
    total = 0.0

    for attr, signal in _BOOLEAN_SIGNALS.items():
        value = getattr(features, attr, None)
        if value:
            total += signal.weight  # weight == cap for booleans

    for attr, signal in _SCALED_SIGNALS.items():
        raw = getattr(features, attr, None)
        if raw is None:
            continue
        # For list-valued fields (e.g. network_domains_contacted) use length
        magnitude = len(raw) if isinstance(raw, (list, set, dict)) else float(raw)
        contribution = min(magnitude * signal.weight, signal.cap)
        total += contribution

    return round(min(total, _SCORE_CEILING), 1)