"""
MobileGuard AI — YARA Engine
Production-grade APK scanning with unpacked content analysis,
metadata-aware severity scoring, and safe failure handling.
"""

import logging
import tempfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
import yara

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────
# Severity weights pulled from rule metadata.
# Rules without an explicit severity tag default to LOW.
# These weights feed directly into the MobileGuard risk scorer.
# ─────────────────────────────────────────────────────────────────
SEVERITY_WEIGHTS: dict[str, float] = {
    "CRITICAL": 100.0,
    "HIGH":      70.0,
    "MEDIUM":    40.0,
    "LOW":       15.0,
}

# Score boost passed to risk_scorer.py per matched rule tier.
# Additive — multiple matches accumulate but are capped upstream.
SCORE_BOOSTS: dict[str, float] = {
    "CRITICAL": 25.0,
    "HIGH":     15.0,
    "MEDIUM":    8.0,
    "LOW":       3.0,
}

# APK internal paths worth scanning — scanning the raw ZIP bytes
# misses strings inside DEX bytecode and parsed XML manifests.
SCAN_TARGETS = [
    "AndroidManifest.xml",   # permissions, receivers, intent filters
    "classes.dex",           # primary DEX
    "classes2.dex",          # multidex
    "classes3.dex",
    "classes4.dex",
]
SCAN_NATIVE_SUFFIX = ".so"   # scan all native libraries


# ─────────────────────────────────────────────────────────────────
# Data model
# ─────────────────────────────────────────────────────────────────
@dataclass
class RuleMatch:
    """All information extracted from a single YARA rule match."""
    rule_name:      str
    namespace:      str          # maps to the .yar filename stem
    severity:       str          # CRITICAL / HIGH / MEDIUM / LOW
    action:         str          # BLOCK / ESCALATE / MONITOR / APPROVE
    description:    str
    mitre_attack:   str
    matched_strings: list[str]   # specific strings that triggered the rule
    matched_in:     str          # which APK component matched (e.g. classes.dex)
    weight:         float        # numeric severity weight (0–100)


@dataclass
class YaraResult:
    """
    Full YARA scan result passed to the risk scoring pipeline.

    severity_score  — highest single-rule weight (0–100); use this
                      as the YARA dimension score in risk_scorer.py.
    score_boost     — total additive boost for the risk composite.
                      Cap at 40.0 in risk_scorer to prevent YARA
                      from dominating the ensemble.
    top_action      — most severe recommended action across all matches.
    scan_error      — non-None means the scan itself failed; treat the
                      APK as UNSCANNED, not clean. Escalate manually.
    """
    matches:         list[RuleMatch]
    severity_score:  float                  # 0–100
    score_boost:     float                  # additive to composite
    top_action:      str                    # BLOCK > ESCALATE > MONITOR > APPROVE
    matched_families: list[str]             # deduplicated rule names
    scan_error:      Optional[str] = None   # None = clean scan, str = failed
    scan_duration_ms: int = 0


# ─────────────────────────────────────────────────────────────────
# Engine
# ─────────────────────────────────────────────────────────────────
class YaraEngine:
    """
    Compile YARA rules from the rules directory, then scan unpacked
    APK contents (not raw ZIP bytes) with full metadata extraction.
    """

    ACTION_PRIORITY = ["BLOCK", "ESCALATE", "MONITOR", "APPROVE"]

    def __init__(self, rules_dir: Optional[Path] = None):
        if rules_dir is None:
            rules_dir = Path(__file__).parent / "yara_rules"

        self.rules_dir = rules_dir
        self._compiled: dict[str, yara.Rules] = {}
        self._compile_errors: dict[str, str] = {}
        self._load_rules()

    # ── Rule loading ──────────────────────────────────────────────

    def _load_rules(self) -> None:
        """
        Compile each .yar file independently so one broken rule
        does not disable the entire engine. Log compile errors but
        continue loading valid rules.
        """
        yar_files = sorted(self.rules_dir.glob("*.yar"))
        if not yar_files:
            raise FileNotFoundError(
                f"No .yar files found in {self.rules_dir}. "
                "Place YARA rules in the yara_rules/ directory."
            )

        for yar_path in yar_files:
            try:
                compiled = yara.compile(filepath=str(yar_path))
                self._compiled[yar_path.stem] = compiled
                logger.info("Compiled YARA rules: %s", yar_path.name)
            except yara.SyntaxError as e:
                self._compile_errors[yar_path.stem] = str(e)
                logger.error(
                    "Syntax error in %s — rule excluded: %s",
                    yar_path.name, e
                )

        if not self._compiled:
            logger.warning(
                "No valid YARA rules compiled. "
                f"Errors: {self._compile_errors}"
            )

            self._compiled = {}
            return

        logger.info(
            "YARA engine ready: %d rule files loaded, %d failed.",
            len(self._compiled), len(self._compile_errors)
        )

    # ── Public API ────────────────────────────────────────────────

    def scan(self, apk_path: str) -> YaraResult:
        """
        Unpack the APK and scan each internal component against all
        compiled rules. Returns a fully populated YaraResult.

        Never raises — on any failure, returns a YaraResult with
        scan_error set. The caller must treat scan_error as UNSCANNED,
        not as a clean result.
        """
        import time
        t0 = time.time()

        try:
            all_matches = self._scan_apk_contents(apk_path)
            result = self._build_result(all_matches)
            result.scan_duration_ms = int((time.time() - t0) * 1000)
            return result

        except zipfile.BadZipFile:
            msg = f"File is not a valid APK (bad ZIP): {apk_path}"
            logger.error(msg)
            return YaraResult(
                matches=[], severity_score=0.0, score_boost=0.0,
                top_action="APPROVE", matched_families=[],
                scan_error=msg,
                scan_duration_ms=int((time.time() - t0) * 1000)
            )

        except Exception as e:
            msg = f"YARA scan failed unexpectedly: {type(e).__name__}: {e}"
            logger.exception("Unexpected YARA scan error on %s", apk_path)
            # Do NOT return a clean result — surface the error.
            return YaraResult(
                matches=[], severity_score=0.0, score_boost=0.0,
                top_action="ESCALATE",   # unknown = escalate, not approve
                matched_families=[],
                scan_error=msg,
                scan_duration_ms=int((time.time() - t0) * 1000)
            )

    # ── Internal scanning ─────────────────────────────────────────

    def _scan_apk_contents(self, apk_path: str) -> list[RuleMatch]:
        """
        Extract APK contents into a temp directory and scan:
          1. AndroidManifest.xml
          2. All DEX files (classes.dex, classes2.dex, ...)
          3. All native .so libraries
        This is the correct approach — scanning raw ZIP bytes misses
        strings inside DEX structures and binary XML.
        """
        all_matches: list[RuleMatch] = []

        with tempfile.TemporaryDirectory(prefix="mobileguard_yara_") as tmpdir:
            tmp = Path(tmpdir)

            with zipfile.ZipFile(apk_path, "r") as apk_zip:
                members = apk_zip.namelist()

                # Determine which members to extract and scan
                to_scan: list[str] = []

                for member in members:
                    if (member.startswith("classes") and member.endswith(".dex")) or \
                       member == "AndroidManifest.xml" or \
                       member.endswith(SCAN_NATIVE_SUFFIX):
                        to_scan.append(member)

                for target in SCAN_TARGETS:
                    if target in members:
                        to_scan.append(target)

                for member in members:
                    if member.endswith(SCAN_NATIVE_SUFFIX):
                        to_scan.append(member)

                # Extract only what we need — don't unzip the whole APK
                for member in to_scan:
                    try:
                        apk_zip.extract(member, path=tmpdir)
                    except Exception as e:
                        logger.warning("Could not extract %s: %s", member, e)
                        continue

                    extracted_path = tmp / member
                    if not extracted_path.exists():
                        continue

                    component_matches = self._scan_file(
                        str(extracted_path),
                        component_name=member
                    )
                    all_matches.extend(component_matches)

        return all_matches

    def _scan_file(self, file_path: str, component_name: str) -> list[RuleMatch]:
        """Run all compiled rule sets against a single extracted file."""
        matches: list[RuleMatch] = []

        for namespace, compiled_rules in self._compiled.items():
            try:
                raw_matches = compiled_rules.match(file_path, timeout=30)
            except yara.TimeoutError:
                logger.warning(
                    "YARA timeout scanning %s with rules %s",
                    component_name, namespace
                )
                continue
            except Exception as e:
                logger.error(
                    "Error scanning %s with %s: %s",
                    component_name, namespace, e
                )
                continue

            for m in raw_matches:
                meta = m.meta  # dict from rule's `meta:` block

                severity  = meta.get("severity", "LOW").upper()
                action    = meta.get("action", "MONITOR").upper()
                desc      = meta.get("description", "No description provided.")
                mitre     = meta.get("mitre_attack", "")

                # Extract the actual strings that triggered the match
                matched_strings = []
                for string_match in m.strings:
                    for instance in string_match.instances:
                        try:
                            decoded = instance.matched_data.decode(
                                "utf-8", errors="replace"
                            )
                            matched_strings.append(decoded[:120])  # cap length
                        except Exception:
                            pass

                matches.append(RuleMatch(
                    rule_name=m.rule,
                    namespace=namespace,
                    severity=severity,
                    action=action,
                    description=desc,
                    mitre_attack=mitre,
                    matched_strings=list(dict.fromkeys(matched_strings)),  # dedup
                    matched_in=component_name,
                    weight=SEVERITY_WEIGHTS.get(severity, 15.0),
                ))

        return matches

    # ── Result assembly ───────────────────────────────────────────

    def _build_result(self, matches: list[RuleMatch]) -> YaraResult:
        """
        Aggregate individual rule matches into a single YaraResult.

        severity_score = highest single weight (not sum — one CRITICAL
        match is enough to flag the APK regardless of how many LOW
        matches also fired).

        score_boost = sum of all boosts, giving multi-match APKs a
        higher composite risk score than single-match APKs.
        """
        if not matches:
            return YaraResult(
                matches=[],
                severity_score=0.0,
                score_boost=0.0,
                top_action="APPROVE",
                matched_families=[],
            )

        # Deduplicate by rule name (same rule can match in multiple
        # DEX files — count it once for scoring)
        seen_rules: set[str] = set()
        deduped: list[RuleMatch] = []
        for m in matches:
            if m.rule_name not in seen_rules:
                seen_rules.add(m.rule_name)
                deduped.append(m)

        severity_score = max(m.weight for m in deduped)

        score_boost = min(
            sum(SCORE_BOOSTS.get(m.severity, 3.0) for m in deduped),
            40.0    # hard cap — YARA is one signal, not the whole score
        )

        top_action = self._highest_action(
            [m.action for m in deduped]
        )

        matched_families = sorted({m.rule_name for m in deduped})

        return YaraResult(
            matches=matches,           # full list including cross-component dupes
            severity_score=severity_score,
            score_boost=score_boost,
            top_action=top_action,
            matched_families=matched_families,
        )

    def _highest_action(self, actions: list[str]) -> str:
        """Return the most severe action from a list."""
        for action in self.ACTION_PRIORITY:
            if action in actions:
                return action
        return "APPROVE"

    # ── Diagnostics ───────────────────────────────────────────────

    def status(self) -> dict:
        """Return engine health — expose this via GET /health."""
        return {
            "rules_loaded": list(self._compiled.keys()),
            "rules_failed": self._compile_errors,
            "total_rule_files": len(self._compiled) + len(self._compile_errors),
        }