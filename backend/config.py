from pathlib import Path
from dotenv import load_dotenv
import os

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent

DATA_DIR = BASE_DIR / "data"
MODEL_DIR = BASE_DIR / "models"

DATA_DIR.mkdir(exist_ok=True)
MODEL_DIR.mkdir(exist_ok=True)

GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "")
VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")

FEATURE_CACHE_DB = str(DATA_DIR / "feature_cache.sqlite")
AUDIT_LOG_PATH = str(DATA_DIR / "audit.jsonl")

MODEL_PATH = str(MODEL_DIR / "xgboost_mobileguard.json")

CERTINTEL_IOC_PATH = str(DATA_DIR / "certin_iocs.json")
C2_BLOCKLIST_PATH = str(DATA_DIR / "c2_ips.txt")

MODEL_VERSION = "1.1"
PIPELINE_VERSION = "1.0"