import subprocess
from pathlib import Path
from ...config import Config
from ...models.vuln import Vulnerability, RiskLevel

class SQLMapInjector:
    def __init__(self, host):
        self.host = host
        self.sql_dir = Path(f"{Config.OUTPUT_BASE}/sqlmap")
        self.sql_dir.mkdir(parents=True, exist_ok=True)
    
    def attack(self):
        vulns = []
        print("   💉 SQLMap Automático...")
        
        for port, service in list(self.host.ports_open.items())[:3]:
            if 'http' in service['service'].lower():
                for endpoint in Config.SQL_ENDPOINTS:
                    url = f"http://{self.host.ip}:{port}{endpoint}"
                    output_dir = self.sql_dir / f"sql_{self.host.ip}_{port}"
                    output_dir.mkdir(exist_ok=True)
                    
                    cmd = [
                        'sqlmap', '-u', url, '--batch', '--risk=2', '--level=2',
                        '--threads=3', f'--output-dir={output_dir}'
                    ]
                    
                    try:
                        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
                        if 'injectable' in result.stdout.lower():
                            vuln = Vulnerability(
                                name="💉 SQL INJECTION CONFIRMADA",
                                description=f"SQLi en: {url}",
                                port=port,
                                risk=RiskLevel.CRITICAL,
                                evidence_file=str(output_dir),
                                recommendations="Prepared Statements, WAF"
                            )
                            vulns.append(vuln)
                            print(f"   💥 SQLi CRÍTICO!")
                    except:
                        pass
        return vulns
