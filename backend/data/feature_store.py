import json
from datetime import datetime
from backend import config
import os

_SQLALCHEMY_AVAILABLE = False
try:
    from sqlalchemy import create_engine, Column, String, Float, Text, DateTime
    from sqlalchemy.orm import declarative_base, sessionmaker
    Base = declarative_base()
    _SQLALCHEMY_AVAILABLE = True
except ImportError:
    Base = object

# Only define the ORM model when SQLAlchemy is present.
# If Base is plain `object`, Column/etc. don't exist and the class body would
# raise NameError at import time.
if _SQLALCHEMY_AVAILABLE:
    class AnalysisCache(Base):
        __tablename__ = 'analysis_cache'
        apk_hash = Column(String, primary_key=True)
        filename = Column(String)
        composite_score = Column(Float)
        action = Column(String)
        full_result_json = Column(Text)
        analyzed_at = Column(DateTime, default=datetime.utcnow)
        model_version = Column(String)
else:
    AnalysisCache = None  # type: ignore

class FeatureStore:
    def __init__(self, db_path=f"sqlite:///{config.FEATURE_CACHE_DB}"):
        self.Session = None
        if not _SQLALCHEMY_AVAILABLE:
            print("Warning: SQLAlchemy not installed. FeatureStore disabled.")
            return
        try:
            if db_path.startswith("sqlite:///"):
                db_dir = os.path.dirname(
                    config.FEATURE_CACHE_DB
                )
                os.makedirs(
                    db_dir,
                    exist_ok=True
                )
            self.engine = create_engine(db_path)
            Base.metadata.create_all(self.engine)
            self.Session = sessionmaker(bind=self.engine)
        except Exception as e:
            print(f"Warning: Failed to init FeatureStore DB: {e}")
            self.Session = None

    def get(self, apk_hash: str, model_version=config.MODEL_VERSION):
        if not self.Session: return None
        session = self.Session()
        try:
            record = session.query(AnalysisCache).filter_by(apk_hash=apk_hash, model_version=model_version).first()
            if record:
                return json.loads(record.full_result_json)
        finally:
            session.close()
        return None

    def cache(self, apk_hash: str, result, model_version=config.MODEL_VERSION):
        if not self.Session: return
        session = self.Session()
        try:
            res_dict = result if isinstance(result, dict) else __import__('dataclasses').asdict(result)
            score = res_dict.get('score', {}).get('composite_score', 0.0)
            action = res_dict.get('score', {}).get('action', 'UNKNOWN')
            
            record = AnalysisCache(
                apk_hash=apk_hash,
                filename=res_dict.get('filename', 'unknown'),
                composite_score=score,
                action=action,
                full_result_json=json.dumps(res_dict),
                model_version=model_version
            )
            session.merge(record)
            session.commit()
        except Exception as e:
            session.rollback()
            print(f"Warning: Failed to cache result: {e}")
        finally:
            session.close()

    def list(self, limit: int = 50, offset: int = 0):
        if not self.Session: return []
        session = self.Session()
        try:
            records = session.query(AnalysisCache).order_by(AnalysisCache.analyzed_at.desc()).limit(limit).offset(offset).all()
            return [{"apk_hash": r.apk_hash, "filename": r.filename, "score": r.composite_score, "action": r.action, "analyzed_at": r.analyzed_at.isoformat()} for r in records]
        finally:
            session.close()
            
    def delete(self, apk_hash: str):
        if not self.Session: return
        session = self.Session()
        try:
            session.query(AnalysisCache).filter_by(apk_hash=apk_hash).delete()
            session.commit()
        finally:
            session.close()
