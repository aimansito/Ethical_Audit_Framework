#!/usr/bin/env python3
import subprocess
import sys
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt, Confirm
from rich import print as rprint
from audit_engine import AuditEngine
from config import Config

console = Console()

TARGET = Config.DEFAULT_TARGET  # 192.168.56.102


def main_menu():
    while True:
        console.clear()

        # Banner
        console.print(Panel(
            "[bold cyan]🛡️  ETHICAL AUDIT FRAMEWORK[/bold cyan]\n"
            f"[dim]Target por defecto: {TARGET}[/dim]",
            border_style="bold blue",
            padding=(1, 2)
        ))

        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Opción", style="cyan", width=8)
        table.add_column("Ataque", style="white", width=40)
        table.add_column("Herramientas", style="green", width=25)

        table.add_row("1", "🚀 Auditoría Completa (DVWA + WordPress)", "Nmap + SQLMap + WPScan")
        table.add_row("2", "🔍 Solo Reconocimiento", "Nmap (puertos + servicios)")
        table.add_row("3", "💉 Solo SQL Injection (DVWA)", "SQLMap --dump (credenciales)")
        table.add_row("4", "🔓 Solo WordPress Brute-Force", "WPScan + Diccionario")
        table.add_row("5", "📝 Auditoría Completa (IP Manual)", "Nmap + SQLMap + WPScan")
        table.add_row("0", "❌ Salir", "")

        console.print(table)
        console.print()

        choice = Prompt.ask(
            "[bold]Selecciona opción[/bold]",
            choices=["0", "1", "2", "3", "4", "5"]
        )

        if choice == "0":
            rprint("[blue]👋 ¡Hasta luego![/blue]")
            break

        elif choice == "1":
            # Auditoría completa contra target por defecto
            rprint(f"\n[bold green]🚀 Auditoría completa contra {TARGET}[/bold green]")
            AuditEngine(TARGET).run_full_audit()

        elif choice == "2":
            # Solo Nmap
            ip = Prompt.ask("IP para escaneo", default=TARGET)
            rprint(f"\n[bold cyan]🔍 Reconocimiento: {ip}[/bold cyan]")
            from services.nmap_scanner import NmapScanner
            host = NmapScanner(ip).full_scan()
            rprint(f"\n[green]✅ {len(host.ports_open)} puertos abiertos en {ip}[/green]")
            for port, info in host.ports_open.items():
                rprint(f"   [cyan]{port}[/cyan] → {info['service']} {info['version']}")

        elif choice == "3":
            # Solo SQLi contra DVWA
            ip = Prompt.ask("IP del target DVWA", default=TARGET)
            rprint(f"\n[bold red]💉 SQL Injection contra DVWA en {ip}[/bold red]")
            from services.nmap_scanner import NmapScanner
            from services.sqlmap_inject import SQLMapInjector
            host = NmapScanner(ip).full_scan()
            sql_vulns = SQLMapInjector(host).attack()
            host.vulnerabilities.extend(sql_vulns)
            if host.credentials:
                rprint(f"\n[bold green]🔑 CREDENCIALES EXTRAÍDAS:[/bold green]")
                for cred in host.credentials:
                    rprint(f"   👤 {cred['user']} : {cred['password']} ({cred['source']})")
            else:
                rprint("[yellow]⚠️ No se extrajeron credenciales[/yellow]")

        elif choice == "4":
            # Solo WordPress
            ip = Prompt.ask("IP del target WordPress", default=TARGET)
            rprint(f"\n[bold magenta]🔓 WordPress Brute-Force: {ip}[/bold magenta]")
            from services.nmap_scanner import NmapScanner
            from services.wpforce_brute import WPForceBrute
            host = NmapScanner(ip).full_scan()
            wp_vulns = WPForceBrute(host).attack()
            host.vulnerabilities.extend(wp_vulns)
            if host.credentials:
                rprint(f"\n[bold green]🔑 CREDENCIALES WORDPRESS:[/bold green]")
                for cred in host.credentials:
                    rprint(f"   👤 {cred['user']} : {cred['password']}")

        elif choice == "5":
            # IP manual
            ip = Prompt.ask("IP objetivo")
            rprint(f"\n[bold green]🚀 Auditoría completa contra {ip}[/bold green]")
            AuditEngine(ip).run_full_audit()

        console.print()
        if not Confirm.ask("¿Otra auditoría?", default=False):
            rprint("[blue]👋 ¡Hasta luego![/blue]")
            break


if __name__ == '__main__':
    try:
        main_menu()
    except KeyboardInterrupt:
        rprint("\n[blue]👋 ¡Hasta luego![/blue]")
