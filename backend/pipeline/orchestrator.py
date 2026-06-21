import os
import time
import uuid
import dataclasses
import json
import hashlib
try:
    from backend.pipeline.static_analyzer import StaticAnalyzer
    from backend.pipeline.dynamic_analyzer import DynamicAnalyzer
    from backend.pipeline.llm_analyzer import LLMAnalyzer
    from backend.pipeline.risk_scorer import RiskScorer
    from backend.pipeline.report_generator import ReportGenerator
    from backend.data.feature_store import FeatureStore
    from backend.data.audit_logger import AuditLogger
    from backend.dataset_feature_extractor import extract_from_apk
    from backend import config
    from backend.detection.yara_engine import YaraEngine
    from backend.intel.mitre_mapper import MitreMapper
    from backend.intel.family_classifier import FamilyClassifier
except ImportError:
    pass

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
    def __init__(self):
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

            mitre_findings = (
                self.mitre_mapper.map_findings(
                    static.permission_list,
                    static.top_apis
                )
            )

            family = (
                self.family_classifier.classify(
                    static.permission_list,
                    static.top_apis
                )
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

            yield PipelineEvent(stage="risk_scoring", status="running", progress=60)
            dataset_features = extract_from_apk(apk_path)
            
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

            if score.composite_score > 40:

                yield PipelineEvent(
                    stage="llm_analysis",
                    status="running",
                    progress=80
                )

                llm = self.llm_analyzer.analyze(
                    static,
                    dynamic
                )

                score = self.risk_scorer.score(
                    static,
                    dynamic,
                    llm,
                    dataset_features,
                    yara_result
                )
            else:

                yield PipelineEvent(
                    stage="llm_skipped",
                    status="done",
                    progress=80
                )

                llm = fallback_llm


            yield PipelineEvent(stage="report_generation", status="running", progress=90)
            report = self.report_generator.generate(static, dynamic, llm, score, yara_result,mitre_findings,family)

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
                yara=dataclasses.asdict(yara_result)
            )

            # We will wire up FeatureStore and AuditLogger in Module 9
            self.feature_store.cache(static.apk_hash, result, config.MODEL_VERSION)
            self.audit_logger.log(result)

            yield PipelineEvent(stage="complete", status="done", progress=100, result=result)

        except Exception as e:
            yield PipelineEvent(stage="error", status="failed", progress=100, error=str(e))
        finally:
            self.cleanup_temp(apk_path)
