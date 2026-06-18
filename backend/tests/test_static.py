import os
import pytest
from fastapi import HTTPException
from backend.pipeline.static_analyzer import StaticAnalyzer

def test_valid_apk_returns_static_features():
    pass

def test_non_apk_raises_422():
    analyzer = StaticAnalyzer()
    # Use an absolute path to a real non-APK file so the 404 guard doesn't
    # fire before the format check (which raises 422).
    non_apk_path = os.path.join(os.path.dirname(__file__), "..", "requirements.txt")
    non_apk_path = os.path.abspath(non_apk_path)
    with pytest.raises(HTTPException) as exc:
        analyzer.analyze(non_apk_path)
    assert exc.value.status_code == 422

def test_oversized_apk_raises_413():
    pass

def test_permission_danger_scoring_known_malicious():
    pass

def test_cache_hit_returns_immediately():
    pass
