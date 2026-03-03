#!/usr/bin/env python3
import sys
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt, Confirm
from rich import print as rprint
from audit_engine import AuditEngine
from services.nmap_scanner import NmapScanner
from config import Config

console = Console()

TARGET = Config.DEFAULT_TARGET  # 192.168.56.102


def banner():
    console.print(Panel(
        "[bold cyan]🛡️  ETHICAL AUDIT FRAMEWORK v2.0[/bold cyan]\n"
        "[bold white]🔍 Reconnaissance │ 💉 SQLi │ 🔓 WordPress │ 📂 Gobuster │ 🔑 Hash Crack[/bold white]\n"
        f"[dim]Target: {TARGET} │ Network: {Config.DEFAULT_NETWORK}[/dim]",
        border_style="bold blue",
        padding=(1, 2)
    ))


def main_menu():
    while True:
        console.clear()
        banner()

        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Opción", style="cyan", width=8)
        table.add_column("Ataque", style="white", width=45)
        table.add_column("Herramientas", style="green", width=30)

        table.add_row("1", "🚀 Auditoría Completa (DVWA + WordPress)", "Nmap+Gobuster+SQLMap+WPScan+Crack")
        table.add_row("2", "🌐 Auto-Discover Red + Auditoría", "Nmap discovery + Full Attack")
        table.add_row("3", "🔍 Solo Reconocimiento + Directorios", "Nmap + Gobuster")
        table.add_row("4", "💉 Solo SQL Injection (DVWA)", "SQLMap --dump + Hash Crack")
        table.add_row("5", "🔓 Solo WordPress Brute-Force", "WPScan + rockyou.txt")
        table.add_row("6", "📝 Auditoría Completa (IP Manual)", "Todo contra IP personalizada")
        table.add_row("0", "❌ Salir", "")

        console.print(table)
        console.print()

        choice = Prompt.ask(
            "[bold]Selecciona opción[/bold]",
            choices=["0", "1", "2", "3", "4", "5", "6"]
        )

        if choice == "0":
            rprint("[blue]👋 ¡Hasta luego![/blue]")
            break

        elif choice == "1":
            # Auditoría completa contra target por defecto
            rprint(f"\n[bold green]🚀 Auditoría completa contra {TARGET}[/bold green]")
            AuditEngine(TARGET).run_full_audit()

        elif choice == "2":
            # Auto-discover red
            network = Prompt.ask("Red a escanear", default=Config.DEFAULT_NETWORK)
            hosts = NmapScanner.discover_network(network)

            if hosts:
                for ip in hosts:
                    if Confirm.ask(f"\n   🎯 ¿Atacar {ip}?", default=True):
                        AuditEngine(ip).run_full_audit()
            else:
                rprint("[red]❌ No se encontraron hosts[/red]")

        elif choice == "3":
            # Solo Nmap + Gobuster
            ip = Prompt.ask("IP para escaneo", default=TARGET)
            rprint(f"\n[bold cyan]🔍 Reconocimiento: {ip}[/bold cyan]")

            host = NmapScanner(ip).full_scan()

            from services.gobuster_enum import GobusterEnum
            rprint(f"\n[bold cyan]📂 Enumeración de directorios: {ip}[/bold cyan]")
            dirs = GobusterEnum(host).enumerate()

            rprint(f"\n[green]✅ {len(host.ports_open)} puertos | {len(dirs)} directorios[/green]")

        elif choice == "4":
            # Solo SQLi contra DVWA
            ip = Prompt.ask("IP del target DVWA", default=TARGET)
            rprint(f"\n[bold red]💉 SQL Injection contra DVWA en {ip}[/bold red]")

            host = NmapScanner(ip).full_scan()

            from services.sqlmap_inject import SQLMapInjector
            sql_vulns = SQLMapInjector(host).attack()
            host.vulnerabilities.extend(sql_vulns)

            # Crackear hashes
            if host.credentials:
                from services.hash_cracker import HashCracker
                rprint(f"\n[bold yellow]🔓 Crackeando hashes...[/bold yellow]")
                HashCracker.crack_credentials(host.credentials)

                rprint(f"\n[bold green]🔑 CREDENCIALES:[/bold green]")
                for cred in host.credentials:
                    rprint(f"   👤 {cred['user']} : {cred['password']} ({cred['source']})")

        elif choice == "5":
            # Solo WordPress
            ip = Prompt.ask("IP del target WordPress", default=TARGET)
            rprint(f"\n[bold magenta]🔓 WordPress Brute-Force: {ip}[/bold magenta]")

            host = NmapScanner(ip).full_scan()

            from services.wpforce_brute import WPForceBrute
            wp_vulns = WPForceBrute(host).attack()
            host.vulnerabilities.extend(wp_vulns)

            if host.credentials:
                rprint(f"\n[bold green]🔑 CREDENCIALES WORDPRESS:[/bold green]")
                for cred in host.credentials:
                    rprint(f"   👤 {cred['user']} : {cred['password']}")

        elif choice == "6":
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
