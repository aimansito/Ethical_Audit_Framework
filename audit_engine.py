from services.nmap_scanner import NmapScanner
from services.wpforce_brute import WPForceBrute
from services.sqlmap_inject import SQLMapInjector
from services.risk_analyzer import RiskAnalyzer
from reporter.pdf_generator import PDFReportGenerator
from config import Config
from models.host import Host

class AuditEngine:
    def __init__(self, target_ip):
        self.target_ip = target_ip
        self.host = None
    
    def run_full_audit(self):
        print(f"\n{'='*60}")
        print(f"🔥 AUDITORÍA COMPLETA: {self.target_ip}")
        print(f"{'='*60}")
        
        # 1. RECON
        self.host = NmapScanner(self.target_ip).full_scan()
        
        # 2. WORDPRESS WPFORCE
        wp_vulns = WPForceBrute(self.host).attack()
        self.host.vulnerabilities.extend(wp_vulns)
        
        # 3. SQLI
        sql_vulns = SQLMapInjector(self.host).attack()
        self.host.vulnerabilities.extend(sql_vulns)
        
        # 4. RIESGO
        RiskAnalyzer.analyze(self.host)
        
        # 5. REPORTE PDF
        PDFReportGenerator(self.host).generate()
        
        print(f"\n🎉 AUDITORÍA TERMINADA!")
        print(f"📁 Resultados: outputs/")
        print(f"📄 Reporte: REPORT_{self.target_ip}*.pdf")
