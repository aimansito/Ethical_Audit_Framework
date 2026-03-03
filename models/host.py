from typing import Dict, List
from .vuln import Vulnerability, RiskLevel

class Host:
    def __init__(self, ip: str):
        self.ip = ip
        self.ports_open: Dict[int, dict] = {}
        self.vulnerabilities: List[Vulnerability] = []
        self.credentials: List[dict] = []
        self.directories: List[dict] = []
        self.os_detection: str = "No detectado"
        self.risk_level: RiskLevel = RiskLevel.LOW
