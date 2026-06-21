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
    def generate(self, static: 'StaticFeatures', dynamic: 'DynamicFeatures', llm: 'LLMFeatures', score: 'RiskScore', yara_result, mitre_findings, family_result) -> ThreatReport:
        
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

        report_lines.append(
            f"ML MALWARE PROBABILITY: {score.ml_score:.2f}%"
        )

        report_lines.append(
            f"VIRUSTOTAL: "
            f"{static.vt_malicious_count} malicious, "
            f"{static.vt_suspicious_count} suspicious"
        )

        report_lines.append("")
        report_lines.append("YARA MATCHES:")

        for rule in yara_result.matched_families:
            report_lines.append(f"  - {rule}")

        report_lines.append("")
        report_lines.append("MALWARE FAMILY:")
        report_lines.append(
            f"  {family_result.family}"
        )

        report_lines.append("")
        report_lines.append("MITRE ATT&CK MOBILE:")
        for t in mitre_findings.techniques:
            report_lines.append(
                f"  - {t.technique_id}: {t.name}"
            )
        
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
