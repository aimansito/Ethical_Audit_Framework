from services.nmap_scanner import NmapScanner
from services.wpforce_brute import WPForceBrute
from services.sqlmap_inject import SQLMapInjector
from services.gobuster_enum import GobusterEnum
from services.hash_cracker import HashCracker
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
        rprint(f"\n[bold red]{'='*60}[/bold red]")
        rprint(f"[bold red]🔥 AUDITORÍA COMPLETA: {self.target_ip}[/bold red]")
        rprint(f"[bold red]{'='*60}[/bold red]")

        # ═══════════════════════════════════════════
        # FASE 1: RECONOCIMIENTO (Nmap)
        # ═══════════════════════════════════════════
        rprint(f"\n[bold cyan]┌─────────────────────────────────────────┐[/bold cyan]")
        rprint(f"[bold cyan]│  FASE 1: 🔍 RECONOCIMIENTO (Nmap)       │[/bold cyan]")
        rprint(f"[bold cyan]└─────────────────────────────────────────┘[/bold cyan]")
        self.host = NmapScanner(self.target_ip).full_scan()

        # ═══════════════════════════════════════════
        # FASE 2: ENUMERACIÓN DIRECTORIOS (Gobuster)
        # ═══════════════════════════════════════════
        rprint(f"\n[bold cyan]┌─────────────────────────────────────────┐[/bold cyan]")
        rprint(f"[bold cyan]│  FASE 2: 📂 DIRECTORIOS (Gobuster)      │[/bold cyan]")
        rprint(f"[bold cyan]└─────────────────────────────────────────┘[/bold cyan]")
        dirs = GobusterEnum(self.host).enumerate()
        self.host.directories = dirs

        # ═══════════════════════════════════════════
        # FASE 3: SQL INJECTION + DUMP (DVWA)
        # ═══════════════════════════════════════════
        rprint(f"\n[bold cyan]┌─────────────────────────────────────────┐[/bold cyan]")
        rprint(f"[bold cyan]│  FASE 3: 💉 SQL INJECTION (DVWA)        │[/bold cyan]")
        rprint(f"[bold cyan]└─────────────────────────────────────────┘[/bold cyan]")
        sql_vulns = SQLMapInjector(self.host).attack()
        self.host.vulnerabilities.extend(sql_vulns)

        # ═══════════════════════════════════════════
        # FASE 4: WORDPRESS (WPScan + Brute-Force)
        # ═══════════════════════════════════════════
        rprint(f"\n[bold cyan]┌─────────────────────────────────────────┐[/bold cyan]")
        rprint(f"[bold cyan]│  FASE 4: 🔓 WORDPRESS (WPScan)          │[/bold cyan]")
        rprint(f"[bold cyan]└─────────────────────────────────────────┘[/bold cyan]")
        wp_vulns = WPForceBrute(self.host).attack()
        self.host.vulnerabilities.extend(wp_vulns)

        # ═══════════════════════════════════════════
        # FASE 5: CRACKEO DE HASHES
        # ═══════════════════════════════════════════
        if self.host.credentials:
            rprint(f"\n[bold cyan]┌─────────────────────────────────────────┐[/bold cyan]")
            rprint(f"[bold cyan]│  FASE 5: 🔓 CRACKEO HASHES (MD5)       │[/bold cyan]")
            rprint(f"[bold cyan]└─────────────────────────────────────────┘[/bold cyan]")
            cracked = HashCracker.crack_credentials(self.host.credentials)
            rprint(f"   [green]✅ {cracked} hash(es) crackeados[/green]")

        # ═══════════════════════════════════════════
        # FASE 6: ANÁLISIS DE RIESGO
        # ═══════════════════════════════════════════
        rprint(f"\n[bold cyan]┌─────────────────────────────────────────┐[/bold cyan]")
        rprint(f"[bold cyan]│  FASE 6: 🎯 ANÁLISIS DE RIESGO          │[/bold cyan]")
        rprint(f"[bold cyan]└─────────────────────────────────────────┘[/bold cyan]")
        RiskAnalyzer.analyze(self.host)

        # ═══════════════════════════════════════════
        # RESUMEN DE CREDENCIALES
        # ═══════════════════════════════════════════
        if self.host.credentials:
            rprint(f"\n[bold red]{'='*60}[/bold red]")
            rprint(f"[bold red]🔑 CREDENCIALES EXTRAÍDAS: {len(self.host.credentials)}[/bold red]")
            rprint(f"[bold red]{'='*60}[/bold red]")
            rprint(f"\n   [bold]{'FUENTE':<22} {'USUARIO':<15} {'CONTRASEÑA'}[/bold]")
            rprint(f"   {'─'*55}")
            for cred in self.host.credentials:
                src = cred.get('source', 'N/A')[:20]
                user = cred.get('user', 'N/A')
                pwd = cred.get('password', 'N/A')
                cracked = '✅' if cred.get('cracked') else '🔒'
                rprint(f"   [green]{src:<22} {user:<15} {pwd} {cracked}[/green]")

        # ═══════════════════════════════════════════
        # REPORTE PDF
        # ═══════════════════════════════════════════
        rprint(f"\n[bold cyan]┌─────────────────────────────────────────┐[/bold cyan]")
        rprint(f"[bold cyan]│  📄 GENERANDO REPORTE PDF               │[/bold cyan]")
        rprint(f"[bold cyan]└─────────────────────────────────────────┘[/bold cyan]")
        PDFReportGenerator(self.host).generate()

        # ═══════════════════════════════════════════
        # RESUMEN FINAL
        # ═══════════════════════════════════════════
        rprint(f"\n[bold green]{'='*60}[/bold green]")
        rprint(f"[bold green]✅ AUDITORÍA TERMINADA![/bold green]")
        rprint(f"[bold green]{'='*60}[/bold green]")
        rprint(f"   📊 Puertos abiertos:     {len(self.host.ports_open)}")
        rprint(f"   📂 Directorios encontrados: {len(getattr(self.host, 'directories', []))}")
        rprint(f"   🐛 Vulnerabilidades:     {len(self.host.vulnerabilities)}")
        rprint(f"   🔑 Credenciales:         {len(self.host.credentials)}")
        rprint(f"   🎯 Riesgo:               {self.host.risk_level.value}")
        rprint(f"   📁 Resultados:           outputs/")
        rprint(f"   📄 Reporte PDF:          outputs/REPORT_{self.target_ip.replace('.','_')}_*.pdf")
        rprint(f"[bold green]{'='*60}[/bold green]")
