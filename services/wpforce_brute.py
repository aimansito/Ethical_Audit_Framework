import subprocess
from pathlib import Path
from ...config import Config
from ...models.host import Host
from ...models.vuln import Vulnerability, RiskLevel

class WPForceBrute:
    def __init__(self, host: Host):
        self.host = host
        self.wp_dir = Path(f"{Config.OUTPUT_BASE}/wpscan")
        self.wp_dir.mkdir(parents=True, exist_ok=True)
    
    def attack(self):
        vulns = []
        print("   🔍 WPScan (Herramienta oficial)...")
        
        for port, service in list(self.host.ports_open.items())[:5]:  # Top 5
            if 'http' in service['service'].lower():
                for path in Config.WORDPRESS_PATHS:
                    url = f"http://{self.host.ip}:{port}{path}"
                    output_file = self.wp_dir / f"wpscan_{self.host.ip}_{port}_{path.replace('/','_')}.txt"
                    
                    print(f"   🔓 WPScan: {url}")
                    
                    cmd = [
                        'wpscan', '--url', url,
                        '--enumerate', 'u,vp,ap',
                        '--no-banner', '--disable-tls-checks',
                        f'--output {output_file}'
                    ]
                    
                    try:
                        result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
                        
                        if any(crit in result.stdout.lower() for crit in 
                               ['vulnerable', 'critical', 'high', 'users found']):
                            vuln = Vulnerability(
                                name="🔴 WORDPRESS VULNERABILIDADES WPFORCE",
                                description=f"WPScan detectado: {url}",
                                port=port,
                                risk=RiskLevel.CRITICAL,
                                evidence_file=str(output_file),
                                recommendations="Actualizar WP/Plugins, WAF"
                            )
                            vulns.append(vuln)
                            print(f"   💥 WPFORCE CRÍTICO!")
                            
                    except:
                        print(f"   ⏭️ WPScan timeout")
        
        return vulns
