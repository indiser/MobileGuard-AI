import json
import os

class ThreatIntel:
    def __init__(self, ioc_path="data/certin_iocs.json", c2_path="data/c2_ips.txt"):
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
