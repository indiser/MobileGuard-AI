import os

# API Keys
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")

# App Configuration
MAX_APK_SIZE_MB = int(os.getenv("MAX_APK_SIZE_MB", 150))
SANDBOX_TIMEOUT_SECS = int(os.getenv("SANDBOX_TIMEOUT_SECS", 90))
USE_LIVE_SANDBOX = os.getenv("USE_LIVE_SANDBOX", "false").lower() == "true"

# LLM Configuration
LLM_MODEL = "gemini-2.0-flash"
LLM_MAX_TOKENS = 2048

# Risk Scoring
RISK_THRESHOLDS = {
    "LOW": 25,
    "MEDIUM": 50,
    "HIGH": 75
}

# File Paths
FEATURE_CACHE_DB = "./data/feature_cache.sqlite"
AUDIT_LOG_PATH = "./data/audit.jsonl"
MODEL_PATH = "./models/xgboost_mobileguard.json"
CERTINTEL_IOC_PATH = "./data/certin_iocs.json"
C2_BLOCKLIST_PATH = "./data/c2_ips.txt"
