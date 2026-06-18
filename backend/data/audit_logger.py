import json
import datetime
import os

class AuditLogger:
    def __init__(self, log_dir="data"):
        self.log_dir = log_dir
        os.makedirs(self.log_dir, exist_ok=True)
        
    def _get_log_file(self):
        date_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")
        return os.path.join(self.log_dir, f"audit_{date_str}.jsonl")

    def log(self, result):
        res_dict = result if isinstance(result, dict) else __import__('dataclasses').asdict(result)
        
        entry = {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "apk_hash": res_dict.get('apk_hash', 'unknown'),
            "filename": res_dict.get('filename', 'unknown'),
            "composite_score": res_dict.get('score', {}).get('composite_score', 0.0),
            "action": res_dict.get('score', {}).get('action', 'UNKNOWN'),
            "dimension_scores": res_dict.get('score', {}).get('dimension_scores', {}),
            "top_shap_features": res_dict.get('score', {}).get('shap_top_features', []),
            "model_version": "1.0",
            "pipeline_duration_ms": res_dict.get('total_duration_ms', 0),
            "sandbox_mode": res_dict.get('dynamic', {}).get('sandbox_mode', 'unknown'),
            "llm_available": res_dict.get('llm', {}).get('llm_available', False),
            "ip_address": "127.0.0.1",
            "error": None
        }
        
        try:
            with open(self._get_log_file(), "a") as f:
                f.write(json.dumps(entry) + "\n")
        except Exception as e:
            print(f"Warning: Failed to write audit log: {e}")

    def log_error(self, filename: str, error_msg: str):
        entry = {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "filename": filename,
            "error": error_msg,
            "action": "ERROR"
        }
        try:
            with open(self._get_log_file(), "a") as f:
                f.write(json.dumps(entry) + "\n")
        except Exception as e:
            print(f"Warning: Failed to write error to audit log: {e}")
