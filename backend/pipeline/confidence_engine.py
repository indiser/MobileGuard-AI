class ConfidenceEngine:

    def calculate(
        self,
        ml_probability,
        family_confidence,
        yara_score,
        vt_malicious,
        evidence_findings
    ):
        # 1. Normalize heuristic inputs safely (handles both 0.0-1.0 and 0-100 scales)
        ml_prob = ml_probability if ml_probability <= 1.0 else ml_probability / 100.0
        fam_conf = family_confidence if family_confidence <= 1.0 else family_confidence / 100.0

        # 2. Calculate baseline heuristic probability
        # P(Malicious) = 1 - P(Not ML) * P(Not Family)
        base_prob = 1.0 - ((1.0 - ml_prob) * (1.0 - fam_conf))

        # 3. Establish Hard Evidence Floors
        # Ground truth dictates confidence. If VT or YARA screams, we listen.
        vt_floor = min(vt_malicious * 18.0, 98.0) / 100.0
        yara_floor = min(yara_score * 1.5, 95.0) / 100.0

        # Weight the actual runtime evidence findings
        critical_findings = sum(1 for e in evidence_findings if getattr(e, 'severity', '') == 'CRITICAL')
        high_findings = sum(1 for e in evidence_findings if getattr(e, 'severity', '') == 'HIGH')
        evidence_floor = min((critical_findings * 30.0) + (high_findings * 12.0), 90.0) / 100.0

        # 4. The highest empirical evidence dictates our baseline confidence
        max_floor = max(vt_floor, yara_floor, evidence_floor)

        if max_floor < 0.15:
            final_confidence = base_prob * 0.40  # Slash heuristic confidence by 60%
        else:
            final_confidence = max_floor + ((1.0 - max_floor) * base_prob)

        return round(min(final_confidence * 100.0, 100.0), 2)