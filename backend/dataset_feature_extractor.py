import json
import re
from pathlib import Path
from typing import Dict, Any
try:
    from backend import config
except ImportError:
    pass

FEATURE_COLUMNS_PATH = Path(config.MODEL_DIR) / "feature_columns.json" if hasattr(config, 'MODEL_DIR') else Path("backend/models/feature_columns.json")

class DatasetFeatureExtractor:
    def __init__(self):
        with open(FEATURE_COLUMNS_PATH, "r") as f:
            self.feature_columns = json.load(f)

        self.regex_patterns = {
            "Runtime.exec": r"Runtime\s*\.\s*exec",
            "DexClassLoader": r"DexClassLoader",
            "PathClassLoader": r"PathClassLoader",
            "ClassLoader": r"ClassLoader",
            "ProcessBuilder": r"ProcessBuilder",
            "System.loadLibrary": r"System\s*\.\s*loadLibrary",
            "Runtime.loadLibrary": r"Runtime\s*\.\s*loadLibrary",
            "Runtime.load": r"Runtime\s*\.\s*load",
            "abortBroadcast": r"abortBroadcast",
            "TelephonyManager.getDeviceId": r"getDeviceId",
            "TelephonyManager.getLine1Number": r"getLine1Number",
            "TelephonyManager.getSubscriberId": r"getSubscriberId",
            "TelephonyManager.getSimSerialNumber": r"getSimSerialNumber",
            "android.telephony.SmsManager": r"SmsManager",
            "sendMultipartTextMessage": r"sendMultipartTextMessage",
            "sendDataMessage": r"sendDataMessage",
            "Ljava.lang.Class.forName": r"Class\.forName",
            "defineClass": r"defineClass",
            "findClass": r"findClass",
            "URLClassLoader": r"URLClassLoader",
        }
        # Precompile regexes to execute in microseconds
        self.compiled_regexes = {k: re.compile(v, re.IGNORECASE) for k, v in self.regex_patterns.items()}

    def extract(self, static_features) -> Dict[str, int]:
        features = {feature: 0 for feature in self.feature_columns}

        # 1. Map Permissions (O(1) lookup)
        perms = set(static_features.permission_list)
        for feature in self.feature_columns:
            # Match either exact dataset format ('android.permission.INTERNET') or stripped ('INTERNET')
            if feature in perms or feature.split('.')[-1] in perms:
                features[feature] = 1

        # 2. Map Intents from the string pool
        intent_pool = set(static_features.extracted_strings)
        for feature in self.feature_columns:
            if feature.startswith("android.intent.action."):
                if feature in intent_pool:
                    features[feature] = 1

        # 3. Map API Calls & Code Patterns
        # Combine the structural code and the string pool. Since we bypassed AST decompilation,
        # every external API call invoked by the app physically exists in the string pool.
        code_blob = static_features.decompiled_code + "\n" + "\n".join(
            [s for s in static_features.extracted_strings if type(s) == str and len(s) < 200]
        )

        for feature in self.feature_columns:
            if features[feature] == 1:
                continue 
            if feature in code_blob:
                features[feature] = 1

        for feature, compiled_regex in self.compiled_regexes.items():
            if feature in features and features[feature] == 0:
                if compiled_regex.search(code_blob):
                    features[feature] = 1

        return features

def extract_from_static(static_features) -> Dict[str, int]:
    extractor = DatasetFeatureExtractor()
    return extractor.extract(static_features)