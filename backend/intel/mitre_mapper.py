from dataclasses import dataclass, field
from typing import Optional


@dataclass(frozen=True)
class MitreTechnique:
    technique_id: str           # e.g. "T1636.001"
    name: str                   # e.g. "SMS Messages"
    tactic: str                 # e.g. "Collection"
    parent_id: Optional[str]    # e.g. "T1636" for subtechniques, else None
    source: str                 # which permission / API triggered this

    def __str__(self) -> str:
        parent = f" (sub of {self.parent_id})" if self.parent_id else ""
        return f"[{self.tactic}] {self.technique_id}{parent} – {self.name}  (triggered by: {self.source})"


# ---------------------------------------------------------------------------
# Mapping tables
# ---------------------------------------------------------------------------

# Permission → MITRE Mobile ATT&CK technique
_PERMISSION_MAP: dict[str, dict] = {
    "READ_SMS": {
        "technique_id": "T1636.004",
        "name": "SMS Messages",
        "tactic": "Collection",
        "parent_id": "T1636",
    },
    "RECEIVE_SMS": {
        "technique_id": "T1636.004",
        "name": "SMS Messages",
        "tactic": "Collection",
        "parent_id": "T1636",
    },
    "SEND_SMS": {
        "technique_id": "T1636.004",
        "name": "SMS Messages",
        "tactic": "Collection",
        "parent_id": "T1636",
    },
    "READ_CONTACTS": {
        "technique_id": "T1636.003",
        "name": "Contact List",
        "tactic": "Collection",
        "parent_id": "T1636",
    },
    "READ_CALL_LOG": {
        "technique_id": "T1636.002",
        "name": "Call Log",
        "tactic": "Collection",
        "parent_id": "T1636",
    },
    "BIND_ACCESSIBILITY_SERVICE": {
        "technique_id": "T1417",
        "name": "Input Capture: Accessibility Features",
        "tactic": "Collection",
        "parent_id": None,
    },
    "RECORD_AUDIO": {
        "technique_id": "T1429",
        "name": "Audio Capture",
        "tactic": "Collection",
        "parent_id": None,
    },
    "CAMERA": {
        "technique_id": "T1512",
        "name": "Video Capture",
        "tactic": "Collection",
        "parent_id": None,
    },
    "ACCESS_FINE_LOCATION": {
        "technique_id": "T1430",
        "name": "Location Tracking",
        "tactic": "Collection",
        "parent_id": None,
    },
    "ACCESS_COARSE_LOCATION": {
        "technique_id": "T1430",
        "name": "Location Tracking",
        "tactic": "Collection",
        "parent_id": None,
    },
    "READ_EXTERNAL_STORAGE": {
        "technique_id": "T1533",
        "name": "Data from Local System",
        "tactic": "Collection",
        "parent_id": None,
    },
    "WRITE_EXTERNAL_STORAGE": {
        "technique_id": "T1533",
        "name": "Data from Local System",
        "tactic": "Collection",
        "parent_id": None,
    },
    "RECEIVE_BOOT_COMPLETED": {
        "technique_id": "T1402",
        "name": "Boot or Logon Autostart Execution",
        "tactic": "Persistence",
        "parent_id": None,
    },
    "REQUEST_INSTALL_PACKAGES": {
        "technique_id": "T1474",
        "name": "Supply Chain Compromise: Modify Software",
        "tactic": "Initial Access",
        "parent_id": None,
    },
    "INTERNET": {
        "technique_id": "T1437",
        "name": "Application Layer Protocol",
        "tactic": "Command and Control",
        "parent_id": None,
    },
    "PROCESS_OUTGOING_CALLS": {
        "technique_id": "T1636.002",
        "name": "Call Log",
        "tactic": "Collection",
        "parent_id": "T1636",
    },
}

# Suspicious API / class name → MITRE technique
_API_MAP: dict[str, dict] = {
    "DexClassLoader": {
        "technique_id": "T1407",
        "name": "Download and Execute Code",
        "tactic": "Defense Evasion",
        "parent_id": None,
    },
    "ClassLoader": {
        "technique_id": "T1407",
        "name": "Download and Execute Code",
        "tactic": "Defense Evasion",
        "parent_id": None,
    },
    "Runtime.exec": {
        "technique_id": "T1406",
        "name": "Obfuscated Files or Information: Native Code",
        "tactic": "Defense Evasion",
        "parent_id": None,
    },
    "ProcessBuilder": {
        "technique_id": "T1406",
        "name": "Obfuscated Files or Information: Native Code",
        "tactic": "Defense Evasion",
        "parent_id": None,
    },
    "Cipher": {
        "technique_id": "T1521",
        "name": "Encrypted Channel",
        "tactic": "Command and Control",
        "parent_id": None,
    },
    "HttpsURLConnection": {
        "technique_id": "T1437",
        "name": "Application Layer Protocol",
        "tactic": "Command and Control",
        "parent_id": None,
    },
    "TelephonyManager.getDeviceId": {
        "technique_id": "T1422",
        "name": "System Network Configuration Discovery",
        "tactic": "Discovery",
        "parent_id": None,
    },
    "LocationManager": {
        "technique_id": "T1430",
        "name": "Location Tracking",
        "tactic": "Collection",
        "parent_id": None,
    },
    "SecretKeySpec": {
        "technique_id": "T1521",
        "name": "Encrypted Channel",
        "tactic": "Command and Control",
        "parent_id": None,
    },
    "LockTaskMode": {
        "technique_id": "T1446",
        "name": "Device Lockout",
        "tactic": "Impact",
        "parent_id": None,
    },
}


@dataclass
class MappingResult:
    techniques: list[MitreTechnique] = field(default_factory=list)
    unmapped_permissions: list[str] = field(default_factory=list)
    unmapped_apis: list[str] = field(default_factory=list)

    def by_tactic(self) -> dict[str, list[MitreTechnique]]:
        """Group techniques by tactic for report-style output."""
        grouped: dict[str, list[MitreTechnique]] = {}
        for t in self.techniques:
            grouped.setdefault(t.tactic, []).append(t)
        return dict(sorted(grouped.items()))

    def technique_ids(self) -> list[str]:
        return sorted({t.technique_id for t in self.techniques})

    def summary(self) -> str:
        lines = ["=== MITRE ATT&CK Mobile Mapping ==="]
        for tactic, techs in self.by_tactic().items():
            lines.append(f"\n[{tactic}]")
            for t in techs:
                lines.append(f"  {t.technique_id}  {t.name}  ← {t.source}")
        if self.unmapped_permissions:
            lines.append(f"\nUnmapped permissions: {', '.join(self.unmapped_permissions)}")
        if self.unmapped_apis:
            lines.append(f"Unmapped APIs: {', '.join(self.unmapped_apis)}")
        return "\n".join(lines)


class MitreMapper:
    """
    Maps Android permissions and suspicious API calls to MITRE ATT&CK for
    Mobile techniques.

    Each finding includes the tactic, technique ID, human-readable name, and
    the source signal that triggered it. Duplicate technique IDs from multiple
    sources are deduplicated by default.
    """

    def map_findings(
        self,
        permissions: list[str],
        suspicious_apis: list[str],
        deduplicate: bool = True,
    ) -> MappingResult:
        """
        Map permissions and APIs to MITRE techniques.

        Args:
            permissions:     Android permission strings.
            suspicious_apis: Suspicious API / class names.
            deduplicate:     If True, only the first source that maps to a
                             given technique ID is kept (default True).
                             Set to False to see every triggering signal.

        Returns:
            MappingResult containing matched techniques and any unmapped inputs.
        """
        techniques: list[MitreTechnique] = []
        seen_ids: set[str] = set()
        unmapped_perms: list[str] = []
        unmapped_apis: list[str] = []

        for perm in permissions:
            entry = _PERMISSION_MAP.get(perm)
            if entry is None:
                unmapped_perms.append(perm)
                continue
            tech = self._make_technique(entry, source=perm)
            if deduplicate and tech.technique_id in seen_ids:
                continue
            techniques.append(tech)
            seen_ids.add(tech.technique_id)

        for api in suspicious_apis:
            entry = _API_MAP.get(api)
            if entry is None:
                unmapped_apis.append(api)
                continue
            tech = self._make_technique(entry, source=api)
            if deduplicate and tech.technique_id in seen_ids:
                continue
            techniques.append(tech)
            seen_ids.add(tech.technique_id)

        return MappingResult(
            techniques=techniques,
            unmapped_permissions=unmapped_perms,
            unmapped_apis=unmapped_apis,
        )

    # ------------------------------------------------------------------

    @staticmethod
    def _make_technique(entry: dict, source: str) -> MitreTechnique:
        return MitreTechnique(
            technique_id=entry["technique_id"],
            name=entry["name"],
            tactic=entry["tactic"],
            parent_id=entry.get("parent_id"),
            source=source,
        )