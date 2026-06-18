import pytest
from backend.pipeline.risk_scorer import RiskScorer, RiskScore
from backend.pipeline.static_analyzer import StaticFeatures
from backend.pipeline.dynamic_analyzer import DynamicFeatures
from backend.pipeline.llm_analyzer import LLMFeatures

def get_dummy_features(malicious=False):
    static = StaticFeatures(
        apk_hash="123", package_name="com.test", permission_list=['INTERNET'] if not malicious else ['READ_SMS', 'SEND_SMS', 'INTERNET'],
        permission_danger_score=0.0 if not malicious else 90.0, permission_count=1 if not malicious else 3,
        dangerous_permission_count=0 if not malicious else 2, suspicious_api_count=0 if not malicious else 10,
        api_suspicion_score=0.0 if not malicious else 80.0, top_apis=[], high_entropy_count=0 if not malicious else 50,
        obfuscation_score=0.0 if not malicious else 80.0, suspicious_urls=[], c2_hit_count=0 if not malicious else 2,
        is_self_signed=False, cert_trust_score=100.0 if not malicious else 20.0, has_native_code=False,
        native_risk_score=0.0, receiver_list=[], service_list=[], graph_density=0.1, graph_node_count=10,
        graph_edge_count=10, min_sdk=21, target_sdk=30, analysis_duration_ms=100
    )
    dynamic = DynamicFeatures(
        sandbox_mode="emulated", sms_send_attempts=0 if not malicious else 5, network_domains_contacted=[],
        c2_domains_hit=0 if not malicious else 2, data_exfil_bytes=0, accessibility_service_abused=False if not malicious else True,
        clipboard_hijack_detected=False, silent_install_attempted=False, camera_accessed=False,
        microphone_accessed=False, location_accessed=False, device_admin_requested=False,
        behavioural_anomaly_score=0.0 if not malicious else 95.0, matched_malware_family="Unknown" if not malicious else "BankBot",
        family_similarity_score=0.0 if not malicious else 0.9, analysis_duration_ms=100
    )
    llm = LLMFeatures(
        primary_function="Test App", malicious_behaviors=[], data_collection=[], obfuscation_techniques=[],
        attack_vectors=[], india_specific_risks=[], severity_score=0.0 if not malicious else 0.95,
        confidence=0.9, verdict="APPROVE" if not malicious else "CRITICAL", recommended_action="",
        executive_summary="", zero_day_hypotheses=[], llm_available=True, analysis_duration_ms=100
    )
    return static, dynamic, llm

def test_benign_apk_scores_below_30():
    scorer = RiskScorer()
    static, dynamic, llm = get_dummy_features(malicious=False)
    res = scorer.score(static, dynamic, llm)
    assert res.composite_score < 30.0
    assert res.action == "APPROVE"

def test_malicious_apk_scores_above_65():
    scorer = RiskScorer()
    static, dynamic, llm = get_dummy_features(malicious=True)
    res = scorer.score(static, dynamic, llm)
    assert res.composite_score > 65.0
    assert res.action == "BLOCK"

def test_boost_rules_applied_correctly():
    scorer = RiskScorer()
    static, dynamic, llm = get_dummy_features(malicious=True)
    res = scorer.score(static, dynamic, llm)
    assert len(res.boost_rules_applied) > 0

def test_composite_never_exceeds_100():
    scorer = RiskScorer()
    static, dynamic, llm = get_dummy_features(malicious=True)
    res = scorer.score(static, dynamic, llm)
    assert res.composite_score <= 100.0

def test_composite_never_below_0():
    scorer = RiskScorer()
    static, dynamic, llm = get_dummy_features(malicious=False)
    res = scorer.score(static, dynamic, llm)
    assert res.composite_score >= 0.0
