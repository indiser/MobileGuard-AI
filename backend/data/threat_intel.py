import json
import os
from backend import config
import requests


class ThreatIntel:
    def __init__(self, ioc_path=config.CERTINTEL_IOC_PATH, c2_path=config.C2_BLOCKLIST_PATH):
        self.ioc_path = ioc_path
        self.c2_path = c2_path
        self.iocs = {
            "malicious_ips": set(),
            "malicious_domains": set(),
            "malicious_package_names": set(),
            "malicious_cert_hashes": set()
        }
        self.c2_blocklist = set()
        self._load_data()
        self.vt_cache = {}

    def _load_data(self):
        if os.path.exists(self.ioc_path):
            try:
                with open(self.ioc_path, "r") as f:
                    data = json.load(f)
                    for k in self.iocs.keys():
                        self.iocs[k] = set(data.get(k, []))
            except Exception as e:
                print(f"Warning: Failed to load IOCs: {e}")
                
        if os.path.exists(self.c2_path):
            try:
                with open(self.c2_path, "r") as f:
                    lines = f.readlines()
                    self.c2_blocklist = set([l.strip() for l in lines if l.strip()])
            except Exception as e:
                print(f"Warning: Failed to load C2 blocklist: {e}")

    def is_malicious_ip(self, ip: str) -> bool:
        return ip in self.iocs["malicious_ips"] or ip in self.c2_blocklist
        
    def is_malicious_domain(self, domain: str) -> bool:
        return domain in self.iocs["malicious_domains"]
        
    def is_malicious_package(self, pkg: str) -> bool:
        return pkg in self.iocs["malicious_package_names"]
    
    def query_virustotal_hash(self, sha256):
        api_key = config.VIRUSTOTAL_API_KEY

        if sha256 in self.vt_cache:
            return self.vt_cache[sha256]

        if not api_key:
            return None

        url = f"https://www.virustotal.com/api/v3/files/{sha256}"

        headers = {
            "x-apikey": api_key
        }

        try:
            r = requests.get(
                url,
                headers=headers,
                timeout=5
            )
            if r.status_code == 429:
                print("VirusTotal quota exceeded")
                return None

            if r.status_code == 403:
                print("VirusTotal API key invalid")
                return None
            
            if r.status_code == 200:
                self.vt_cache[sha256] = r.json()
                return r.json()

        except Exception:
            pass

        return None
