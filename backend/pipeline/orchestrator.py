import os
import time
import uuid
import dataclasses
import json
import hashlib
# try:
#     from backend.pipeline.static_analyzer import StaticAnalyzer
#     from backend.pipeline.dynamic_analyzer import DynamicAnalyzer
#     from backend.pipeline.llm_analyzer import LLMAnalyzer
#     from backend.pipeline.risk_scorer import RiskScorer
#     from backend.pipeline.report_generator import ReportGenerator
#     from backend.data.feature_store import FeatureStore
#     from backend.data.audit_logger import AuditLogger
#     from backend.dataset_feature_extractor import extract_from_static
#     from backend import config
#     from backend.detection.yara_engine import YaraEngine
#     from backend.intel.mitre_mapper import MitreMapper
#     from backend.intel.family_classifier import FamilyClassifier
#     from backend.pipeline.evidence_engine import EvidenceEngine
#     from backend.pipeline.confidence_engine import ConfidenceEngine
#     from backend.plugins.plugin_manager import PluginManager
# except ImportError:
#     pass

from backend.pipeline.static_analyzer import StaticAnalyzer
from backend.pipeline.dynamic_analyzer import DynamicAnalyzer
from backend.pipeline.llm_analyzer import LLMAnalyzer
from backend.pipeline.risk_scorer import RiskScorer
from backend.pipeline.report_generator import ReportGenerator
from backend.data.feature_store import FeatureStore
from backend.data.audit_logger import AuditLogger
from backend.dataset_feature_extractor import extract_from_static
from backend import config
from backend.detection.yara_engine import YaraEngine
from backend.intel.mitre_mapper import MitreMapper
from backend.intel.family_classifier import FamilyClassifier
from backend.pipeline.evidence_engine import EvidenceEngine
from backend.pipeline.confidence_engine import ConfidenceEngine
from backend.plugins.plugin_manager import PluginManager

@dataclasses.dataclass
class AnalysisResult:
    apk_hash: str
    filename: str
    static: dict
    dynamic: dict
    llm: dict
    score: dict
    report: dict
    total_duration_ms: int
    mitre: dict
    family: dict
    yara: dict
    confidence_score: float
    evidence_findings: list
    
@dataclasses.dataclass
class PipelineEvent:
    stage: str
    status: str
    progress: int = 0
    error: str = None
    result: AnalysisResult = None
    
    def to_json(self):
        d = {
            "stage": self.stage,
            "status": self.status,
            "progress": self.progress,
        }
        if self.error is not None:
            d["error"] = self.error
        if self.result is not None:
            d["result"] = dataclasses.asdict(self.result)
        return json.dumps(d)

class PipelineOrchestrator:
    def __init__(self, benchmark_mode = False):
        self.benchmark_mode = benchmark_mode
        self.static_analyzer = StaticAnalyzer()
        self.dynamic_analyzer = DynamicAnalyzer()
        self.llm_analyzer = LLMAnalyzer()
        self.risk_scorer = RiskScorer()
        self.report_generator = ReportGenerator()
        self.feature_store = FeatureStore()
        self.audit_logger = AuditLogger()
        self.yara_engine = YaraEngine()
        self.mitre_mapper = MitreMapper()
        self.family_classifier = FamilyClassifier()
        self.evidence_engine = EvidenceEngine()
        self.confidence_engine = ConfidenceEngine()
        self.plugin_manager = PluginManager()

        if self.benchmark_mode:
            print("[!] BENCHMARK MODE ACTIVE: External APIs (VT, LLM) disconnected.")
            # Neutralize VirusTotal and Domain intel network calls in memory
            self.static_analyzer.intel.query_virustotal_hash = lambda h: None
            self.static_analyzer.intel.is_malicious_domain = lambda d: False
        
    def save_to_temp(self, apk_bytes: bytes, filename: str) -> str:
        temp_dir = "temp_apks"
        os.makedirs(temp_dir, exist_ok=True)
        safe_filename = f"{uuid.uuid4()}_{filename}"
        path = os.path.join(temp_dir, safe_filename)
        with open(path, "wb") as f:
            f.write(apk_bytes)
        return path
        
    def cleanup_temp(self, filepath: str):
        if os.path.exists(filepath):
            os.remove(filepath)

    def analyze(self, apk_bytes: bytes, filename: str):
        t0 = time.time()

        apk_hash = hashlib.sha256(apk_bytes).hexdigest()
        cached = self.feature_store.get(apk_hash, config.MODEL_VERSION)
        if cached:
            try:
                cached_result = AnalysisResult(**cached)
                yield PipelineEvent(
                    stage="cache_hit",
                    status="done",
                    progress=20
                )
                yield PipelineEvent(
                    stage="complete",
                    status="done",
                    progress=100,
                    result=cached_result
                )
                return
            except Exception:
                print("Cache entry invalid. Re-analyzing APK.")

        apk_path = self.save_to_temp(apk_bytes, filename)

        try:
            yield PipelineEvent(stage="static_analysis", status="running", progress=10)
            static = self.static_analyzer.analyze(apk_path)

            yield PipelineEvent(
                stage="yara_scan",
                status="running",
                progress=25
            )

            yara_result = self.yara_engine.scan(
                apk_path
            )

            if yara_result.scan_error:

                yield PipelineEvent(
                    stage="yara_scan",
                    status="warning",
                    progress=25,
                    error=yara_result.scan_error
                )


            cached = self.feature_store.get(static.apk_hash, config.MODEL_VERSION)
            if cached:
                try:
                    cached_result = AnalysisResult(**cached)
                    yield PipelineEvent(
                        stage="cache_hit",
                        status="done",
                        progress=20
                    )

                    yield PipelineEvent(
                        stage="complete",
                        status="done",
                        progress=100,
                        result=cached_result
                    )
                    return
                except Exception:
                    print("Cache entry invalid. Re-analyzing APK.")

            yield PipelineEvent(stage="dynamic_analysis", status="running", progress=40)
            dynamic = self.dynamic_analyzer.analyze(apk_path, static.package_name)

            yield PipelineEvent(stage="plugin_execution", status="running", progress=55)
            
            # Run all custom plugins in parallel threads
            plugin_findings = self.plugin_manager.run_plugins(
                static_features=static, 
                dynamic_features=dynamic
            )
            

            yield PipelineEvent(stage="risk_scoring", status="running", progress=60)

            family = self.family_classifier.classify(
                permissions=static.permission_list,
                suspicious_apis=static.top_apis,
                strings=static.extracted_strings,
                runtime_events=dynamic.__dict__
            )

            mitre_findings = (
                self.mitre_mapper.map_findings(
                    permissions=static.permission_list,
                    suspicious_apis=static.top_apis,
                    dynamic_events=dynamic.runtime_events  # Now we pass the actual execution data
                )
            )

            evidence_findings = (
                self.evidence_engine.correlate(
                    static_features=static,
                    dynamic_events=dynamic,
                    yara_hits=yara_result,
                    mitre_hits=mitre_findings,
                    vt_results={
                        "malicious": static.vt_malicious_count,
                        "suspicious": static.vt_suspicious_count
                    }
                )
            )

            if plugin_findings:
                evidence_findings.extend(plugin_findings)

            dataset_features = extract_from_static(static)
            
            fallback_llm = (
                self.llm_analyzer._get_fallback_features()
            )

            score = self.risk_scorer.score(
                static,
                dynamic,
                fallback_llm,
                dataset_features,
                yara_result
            )

            confidence_score = (
                self.confidence_engine.calculate(
                    ml_probability=score.xgb_probability,
                    family_confidence=family.confidence,
                    yara_score=yara_result.severity_score,
                    vt_malicious=static.vt_malicious_count,
                    evidence_findings=evidence_findings
                )
            )

            if score.composite_score > 40 and not self.benchmark_mode:

                yield PipelineEvent(
                    stage="llm_analysis",
                    status="running",
                    progress=80
                )

                llm = self.llm_analyzer.analyze(
                    static,
                    dynamic,
                    family=family,
                    evidence=evidence_findings,
                    confidence_score=confidence_score
                )

                score = self.risk_scorer.score(
                    static,
                    dynamic,
                    llm,
                    dataset_features,
                    yara_result
                )

                confidence_score = (
                    self.confidence_engine.calculate(
                        ml_probability=score.xgb_probability,
                        family_confidence=family.confidence,
                        yara_score=yara_result.severity_score,
                        vt_malicious=static.vt_malicious_count,
                        evidence_findings=evidence_findings
                    )
                )
            else:

                yield PipelineEvent(
                    stage="llm_skipped",
                    status="done",
                    progress=80
                )

                llm = fallback_llm


            yield PipelineEvent(stage="report_generation", status="running", progress=90)
            report = self.report_generator.generate(static, dynamic, llm, score, yara_result,mitre_findings,family,evidence_findings=evidence_findings,confidence_score=confidence_score)

            result = AnalysisResult(
                apk_hash=static.apk_hash,
                filename=filename,
                static=dataclasses.asdict(static),
                dynamic=dataclasses.asdict(dynamic),
                llm=dataclasses.asdict(llm),
                score=dataclasses.asdict(score),
                report=dataclasses.asdict(report),
                total_duration_ms=int((time.time() - t0) * 1000),
                mitre=dataclasses.asdict(mitre_findings),
                family=dataclasses.asdict(family),
                yara=dataclasses.asdict(yara_result),
                confidence_score=confidence_score,
                evidence_findings=[
                    {
                        "finding": f.finding,
                        "severity": f.severity,
                        "confidence": f.confidence,
                        "evidence": f.evidence
                    }
                    for f in evidence_findings
                ]
            )

            # We will wire up FeatureStore and AuditLogger in Module 9
            self.feature_store.cache(static.apk_hash, result, config.MODEL_VERSION)
            self.audit_logger.log(result)

            yield PipelineEvent(stage="complete", status="done", progress=100, result=result)

        except Exception as e:
            yield PipelineEvent(stage="error", status="failed", progress=100, error=str(e))
        finally:
            self.cleanup_temp(apk_path)
