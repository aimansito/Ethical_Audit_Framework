from enum import Enum

class RiskLevel(Enum):
    LOW = "🟢 BAJO"
    MEDIUM = "🟡 MEDIO"
    HIGH = "🟠 ALTO"
    CRITICAL = "🔴 CRÍTICO"

class Vulnerability:
    def __init__(self, name, description, port, risk, evidence_file="", recommendations=""):
        self.name = name
        self.description = description
        self.port = port
        self.risk = risk
        self.evidence_file = evidence_file
        self.recommendations = recommendations
