from services.nmap_scanner import NmapScanner
from services.wpforce_brute import WPForceBrute
from services.sqlmap_inject import SQLMapInjector
from services.risk_analyzer import RiskAnalyzer
from reporter.pdf_generator import PDFReportGenerator
from config import Config
from models.host import Host
from rich import print as rprint


class AuditEngine:
    def __init__(self, target_ip):
        self.target_ip = target_ip
        self.host = None

    def run_full_audit(self):
        print(f"\n{'='*60}")
        print(f"🔥 AUDITORÍA COMPLETA: {self.target_ip}")
        print(f"{'='*60}")

        # 1. RECON
        print(f"\n[FASE 1] 🔍 Reconocimiento (Nmap)")
        self.host = NmapScanner(self.target_ip).full_scan()

        # 2. SQL INJECTION + DUMP
        print(f"\n[FASE 2] 💉 SQL Injection (DVWA)")
        sql_vulns = SQLMapInjector(self.host).attack()
        self.host.vulnerabilities.extend(sql_vulns)

        # 3. WORDPRESS
        print(f"\n[FASE 3] 🔓 WordPress (WPScan + Brute-Force)")
        wp_vulns = WPForceBrute(self.host).attack()
        self.host.vulnerabilities.extend(wp_vulns)

        # 4. ANÁLISIS DE RIESGO
        print(f"\n[FASE 4] 🎯 Análisis de Riesgo")
        RiskAnalyzer.analyze(self.host)

        # 5. RESUMEN CREDENCIALES
        if self.host.credentials:
            print(f"\n{'='*60}")
            rprint(f"[bold green]🔑 CREDENCIALES EXTRAÍDAS: {len(self.host.credentials)}[/bold green]")
            print(f"{'='*60}")
            for cred in self.host.credentials:
                rprint(f"   👤 [cyan]{cred['user']}[/cyan] : [red]{cred['password']}[/red]  ({cred['source']})")

        # 6. REPORTE PDF
        print(f"\n[FASE 5] 📄 Generando Reporte PDF")
        PDFReportGenerator(self.host).generate()

        print(f"\n{'='*60}")
        print(f"🎉 AUDITORÍA TERMINADA!")
        print(f"📁 Resultados: outputs/")
        print(f"📄 Reporte: outputs/REPORT_{self.target_ip.replace('.','_')}_*.pdf")
        print(f"{'='*60}")
