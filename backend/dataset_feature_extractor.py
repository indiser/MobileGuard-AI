from pathlib import Path
import json
import re
from typing import Dict, List
from androguard.misc import AnalyzeAPK
from backend import config
from pathlib import Path
from lxml import etree

FEATURE_COLUMNS_PATH = (
    Path(config.MODEL_DIR)
    / "feature_columns.json"
)


class DatasetFeatureExtractor:
    def __init__(self):
        with open(FEATURE_COLUMNS_PATH, "r") as f:
            self.feature_columns = json.load(f)

    def extract(
        self,
        permissions: List[str],
        manifest_text: str,
        decompiled_code: str,
    ) -> Dict[str, int]:

        features = {
            feature: 0
            for feature in self.feature_columns
        }

        self._extract_permissions(
            features,
            permissions
        )

        self._extract_code_features(
            features,
            decompiled_code
        )

        self._extract_manifest_features(
            features,
            manifest_text
        )

        return features

    def _extract_permissions(
        self,
        features,
        permissions
    ):
        perms = set(permissions)

        for feature in self.feature_columns:
            if feature in perms:
                features[feature] = 1

    def _extract_manifest_features(
        self,
        features,
        manifest_text
    ):
        for feature in self.feature_columns:

            if feature.startswith(
                "android.intent.action."
            ):
                if feature in manifest_text:
                    features[feature] = 1

    def _extract_code_features(
        self,
        features,
        code
    ):
        for feature in self.feature_columns:

            if feature in code:
                features[feature] = 1

        regex_patterns = {
            "Runtime.exec":
                r"Runtime\s*\.\s*exec",

            "DexClassLoader":
                r"DexClassLoader",

            "PathClassLoader":
                r"PathClassLoader",

            "ClassLoader":
                r"ClassLoader",

            "ProcessBuilder":
                r"ProcessBuilder",

            "System.loadLibrary":
                r"System\s*\.\s*loadLibrary",

            "Runtime.loadLibrary":
                r"Runtime\s*\.\s*loadLibrary",

            "Runtime.load":
                r"Runtime\s*\.\s*load",

            "abortBroadcast":
                r"abortBroadcast",

            "TelephonyManager.getDeviceId":
                r"getDeviceId",

            "TelephonyManager.getLine1Number":
                r"getLine1Number",

            "TelephonyManager.getSubscriberId":
                r"getSubscriberId",

            "TelephonyManager.getSimSerialNumber":
                r"getSimSerialNumber",

            "android.telephony.SmsManager":
                r"SmsManager",

            "sendMultipartTextMessage":
                r"sendMultipartTextMessage",

            "sendDataMessage":
                r"sendDataMessage",

            "Ljava.lang.Class.forName":
                r"Class\.forName",

            "defineClass":
                r"defineClass",

            "findClass":
                r"findClass",

            "URLClassLoader":
                r"URLClassLoader",
        }

        for feature, pattern in regex_patterns.items():

            if feature not in features:
                continue

            if re.search(
                pattern,
                code,
                re.IGNORECASE
            ):
                features[feature] = 1


def extract_from_apk(
        apk_path: str
    ):
        a, d, dx = AnalyzeAPK(apk_path)

        permissions = list(
            a.get_permissions()
        )

        manifest_xml = a.get_android_manifest_xml()

        manifest_text = etree.tostring(
            manifest_xml,
            encoding="unicode"
        )

        code_chunks = []

        for cls in d:
            try:
                code_chunks.append(
                    cls.get_source()
                )
            except:
                pass

        code = "\n".join(code_chunks)

        extractor = DatasetFeatureExtractor()

        return extractor.extract(
            permissions,
            manifest_text,
            code
        )
