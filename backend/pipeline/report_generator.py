import datetime
from dataclasses import dataclass
from typing import List

try:
    from backend.pipeline.static_analyzer import StaticFeatures
    from backend.pipeline.dynamic_analyzer import DynamicFeatures
    from backend.pipeline.llm_analyzer import LLMFeatures
    from backend.pipeline.risk_scorer import RiskScore
except ImportError:
    pass

@dataclass
class ThreatReport:
    verdict: str
    risk_score: float
    action: str
    executive_summary: str          # from LLM (2-3 sentences)
    full_report: str                # structured report
    forensic_indicators: List[str]  # top 5 evidence items
    shap_explanation: str
    india_risk_flag: bool
    certintel_flag: bool
    malware_family: str
    report_generated_at: str        # ISO 8601 timestamp

class ReportGenerator:
    def generate(self, static: 'StaticFeatures', dynamic: 'DynamicFeatures', llm: 'LLMFeatures', score: 'RiskScore', yara_result, mitre_findings, family_result, evidence_findings=None, confidence_score=None) -> ThreatReport:
        
        indicators = []
        if static.c2_hit_count > 0:
            indicators.append(f"Hardcoded C2 IPs detected in code")
        if dynamic.c2_domains_hit > 0:
            indicators.append(f"Network traffic to known C2 domains")
        if static.suspicious_api_count > 0:
            indicators.append(f"Suspicious API usage: {', '.join(static.top_apis[:3])}")
        if 'BIND_ACCESSIBILITY_SERVICE' in static.permission_list:
            indicators.append("Requests Accessibility Service (Overlay/Keylogger potential)")
        if dynamic.sms_send_attempts > 0:
            indicators.append("Observed sending unauthorized SMS messages")
        if llm.malicious_behaviors:
            indicators.append(f"LLM identified: {llm.malicious_behaviors[0]}")
            
        if len(indicators) == 0:
            indicators.append("No critical indicators found.")
            
        forensic_indicators = indicators[:5]
        
        india_risk = len(llm.india_specific_risks) > 0 or "UPI" in str(llm.india_specific_risks) or "Bank of India" in static.package_name
        
        action_reason = "App exhibits clear signs of malicious intent." if score.action == "BLOCK" else "App requires further review." if score.action in ["MONITOR", "ESCALATE"] else "App appears benign."
        
        report_lines = [
            f"VERDICT: {score.action} — {action_reason}",
            f"RISK SCORE: {score.composite_score}/100 — " + score.shap_explanation,
            "TECHNICAL FINDINGS:",
            f"  - Permission Analysis: {static.dangerous_permission_count} dangerous permissions requested.",
            f"  - Code Behaviour: {llm.primary_function}. " + (" ".join(llm.malicious_behaviors) if llm.malicious_behaviors else "No specific malicious behavior cited by LLM."),
        ]

        if getattr(static, 'anti_analysis_score', 0) > 0:
            report_lines.append(f"  - Anti-Analysis/Evasion: Score {static.anti_analysis_score:.1f}. Indicators: {', '.join(getattr(static, 'anti_analysis_indicators', []))}")
            
        if getattr(static, 'embedded_apks', 0) > 0 or getattr(static, 'embedded_dex', 0) > 0:
            report_lines.append(f"  - Hidden Payloads: {getattr(static, 'embedded_apks', 0)} APKs, {getattr(static, 'embedded_dex', 0)} DEX files embedded in resources.")
            
        if getattr(static, 'encrypted_blobs', 0) > 0:
            report_lines.append(f"  - Encrypted Assets: {getattr(static, 'encrypted_blobs', 0)} highly obfuscated/encrypted blobs detected.")

        if getattr(static, "crypto_score", 0) > 0:
            report_lines.append(
                f"  - Cryptographic Analysis: "
                f"Score {static.crypto_score:.1f}"
            )
            report_lines.append(
                f"    Algorithms: "
                f"{', '.join(static.crypto_algorithms)}"
            )
            report_lines.append(
                f"    Encrypted Strings: "
                f"{static.encrypted_string_count}"
            )
        
        crypto_ttps = getattr(static, 'crypto_ttps', [])
        if crypto_ttps:
            report_lines.append(f"  - Crypto TTPs: {', '.join(crypto_ttps)}")
        
        hardcoded_secrets = getattr(static, 'hardcoded_secrets', [])
        if hardcoded_secrets:
            report_lines.append("  - [!] HARDCODED SECRETS EXPOSED:")
            for secret in hardcoded_secrets:
                report_lines.append(f"      * {secret}")

        report_lines.append(
            f"ML MALWARE PROBABILITY: {score.ml_score:.2f}%"
        )

        if confidence_score is not None:
            report_lines.append(
                f"ANALYSIS CONFIDENCE: {confidence_score:.2f}%"
            )

        report_lines.append(
            f"VIRUSTOTAL: "
            f"{static.vt_malicious_count} malicious, "
            f"{static.vt_suspicious_count} suspicious"
        )

        report_lines.append("")
        report_lines.append("YARA MATCHES:")

        if yara_result and getattr(yara_result,"matched_families",None):
            for rule in yara_result.matched_families:
                report_lines.append(f"  - {rule}")
        else:
            report_lines.append("  No YARA matches.")

        report_lines.append("")
        report_lines.append("MALWARE FAMILY:")
        if family_result:
            report_lines.append(f"  {getattr(family_result, 'family', 'Unknown')}")
            report_lines.append(f"  Confidence: {getattr(family_result, 'confidence', 0):.1f}%")
        else:
            report_lines.append("  Unknown")
            report_lines.append("  Confidence: 0.0%")

        report_lines.append("")
        report_lines.append("MITRE ATT&CK MOBILE:")

        if hasattr(mitre_findings, 'confirmed_techniques') and mitre_findings.confirmed_techniques:
            report_lines.append("  [CONFIRMED ATTACK CHAINS]")
            for tech in mitre_findings.confirmed_techniques:
                report_lines.append(f"  - {tech.technique_id} ({tech.tactic}): {tech.name} [Confidence: {tech.confidence}%]")
                for ev in tech.evidence:
                    report_lines.append(f"      * {ev}")
        else:
            report_lines.append("  [No dynamic attack chains confirmed]")


        report_lines.append("\n  [STATIC CAPABILITIES]")
        if mitre_findings and hasattr(mitre_findings,"techniques"):
            for t in mitre_findings.techniques:
                report_lines.append(f"  - {t.technique_id}: {t.name}")
        else:
            report_lines.append("  No MITRE techniques identified.")

        
        if dynamic.sandbox_mode == "emulated":
            report_lines.append(
                "  - Network Activity: Dynamic analysis unavailable (emulated mode)."
            )
        else:
            report_lines.append(
                f"  - Network Activity: Contacted {len(dynamic.network_domains_contacted)} domains. C2 hits: {dynamic.c2_domains_hit}."
            )

        report_lines.append(
            f"  - Obfuscation: {static.high_entropy_count} high entropy strings detected (Score: {static.obfuscation_score:.1f})."
        )
        
        if india_risk:
            report_lines.append(f"INDIA-SPECIFIC THREAT: {', '.join(llm.india_specific_risks) if llm.india_specific_risks else 'Potential UPI/OTP overlay risks identified.'}")
            
        report_lines.append(
            "TOP ML FEATURES:"
        )

        for feat, importance in score.shap_top_features:
            report_lines.append(
                f"  - {feat}: {importance:.3f}"
            )

        report_lines.append("")
        report_lines.append("RUNTIME EVENTS:")

        for event in dynamic.runtime_events:

            report_lines.append(
                f"  - {event.event_type.value}"
            )

            report_lines.append(
                f"      Evidence: {event.raw_evidence[:150]}"
            )

            report_lines.append(
                f"      Confidence: {event.confidence:.2f}"
            )

            report_lines.append(
                f"      Source: {event.source}"
            )

            report_lines.append(
                f"      Timestamp: {event.timestamp}"
            )

            if event.mitre_technique:

                report_lines.append(
                    f"      MITRE: {event.mitre_technique}"
                )
            
        report_lines.append("")
        report_lines.append("CORRELATED FINDINGS:")

        for finding in (evidence_findings or []):
            report_lines.append(
                f"  - {finding.finding} "
                f"({finding.confidence}%)"
            )
        
        report_lines.append("")
        report_lines.append(
            f"OVERALL CONFIDENCE: "
            f"{confidence_score:.2f}%"
        )
        
        report_lines.append("RECOMMENDED ACTIONS:")
        
        if score.action == "BLOCK":
            report_lines.append("  1. Immediate: Block application execution and network access.")
            report_lines.append("  2. Investigation: Identify affected devices and reset credentials.")
            if score.composite_score > 75:
                report_lines.append("  3. Reporting: File a formal report with CERT-In.")
        elif score.action == "ESCALATE":
            report_lines.append("  1. Immediate: Quarantine application pending manual analysis.")
            report_lines.append("  2. Investigation: Review forensic indicators for false positives.")
        elif score.action == "MONITOR":
            report_lines.append("  1. Immediate: Allow execution with network monitoring.")
            report_lines.append("  2. Investigation: Periodically review network activity logs.")
        else:
            report_lines.append("  1. Immediate: Approve for general use.")
            
        report_lines.append("EVIDENCE SUMMARY:")
        for idx, ind in enumerate(forensic_indicators, 1):
            report_lines.append(f"  * {ind}")
            
        full_report = "\n".join(report_lines)

        cert_intel_hit = static.c2_hit_count > 0 or dynamic.c2_domains_hit > 0 or static.vt_malicious_count > 0
        
        return ThreatReport(
            verdict=score.action,
            risk_score=score.composite_score,
            action=score.action,
            executive_summary=llm.executive_summary or "No executive summary available.",
            full_report=full_report,
            forensic_indicators=forensic_indicators,
            shap_explanation=score.shap_explanation,
            india_risk_flag=india_risk,
            certintel_flag=cert_intel_hit,
            malware_family=family_result.family,
            report_generated_at=datetime.datetime.now(datetime.timezone.utc).isoformat()
        )
