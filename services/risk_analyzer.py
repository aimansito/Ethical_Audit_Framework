from models.host import Host
from models.vuln import RiskLevel


class RiskAnalyzer:
    @staticmethod
    def analyze(host: Host):
        score = 0

        # Vulnerabilidades
        critical = sum(1 for v in host.vulnerabilities if v.risk == RiskLevel.CRITICAL)
        score += critical * 30

        # Puertos peligrosos
        dangerous = {21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3306, 5432, 5900}
        exposed = sum(1 for p in host.ports_open if p in dangerous)
        score += exposed * 8

        # HTTP expuesto
        http = sum(1 for s in host.ports_open.values() if 'http' in s['service'].lower())
        score += http * 10

        if score >= 60:
            host.risk_level = RiskLevel.CRITICAL
        elif score >= 30:
            host.risk_level = RiskLevel.HIGH
        elif score >= 10:
            host.risk_level = RiskLevel.MEDIUM
        else:
            host.risk_level = RiskLevel.LOW

        print(f"   🎯 RIESGO: {host.risk_level.value} (Score: {score}/100)")
