#!/usr/bin/env python3
import subprocess
import sys
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt, Confirm
from rich import print as rprint
from audit_engine import AuditEngine

console = Console()

def discover_hosts():
    """Auto-descubrir VMs"""
    try:
        result = subprocess.run(['nmap', '-sn', '192.168.56.0/24'], 
                              capture_output=True, text=True, timeout=10)
        ips = []
        for line in result.stdout.split('\n'):
            if 'Nmap scan report for' in line:
                ip = line.split()[-1]
                if ip.startswith('192.168.56.'):
                    ips.append(ip)
        return ips[:3]  # Top 3
    except:
        return ['192.168.56.101']

def main_menu():
    while True:
        console.clear()
        
        table = Table(title="🎯 FRAMEWORK AUDITORÍA ÉTICA PYTHON", show_header=True)
        table.add_column("Opción", style="cyan")
        table.add_column("Objetivo", style="white")
        table.add_column("Herramientas", style="green")
        
        table.add_row("1", "🔍 Auto-descubrir red", "Nmap + WPScan + SQLMap")
        table.add_row("2", "🎯 Metasploitable (101)", "Full Attack")
        table.add_row("3", "📝 IP manual", "Full Attack")
        table.add_row("4", "🛡️ Solo Nmap", "Recon rápido")
        table.add_row("5", "🔓 Solo WPScan", "WordPress")
        table.add_row("0", "❌ Salir", "")
        
        console.print(Panel(table, padding=(1,2), border_style="bold blue"))
        
        choice = Prompt.ask("Selecciona opción", choices=["0","1","2","3","4","5"])
        
        if choice == "0":
            break
        
        elif choice == "1":
            hosts = discover_hosts()
            if hosts:
                for ip in hosts:
                    if Confirm.ask(f"Atacar {ip}?"):
                        AuditEngine(ip).run_full_audit()
            else:
                rprint("[red]❌ No hosts encontrados[/red]")
        
        elif choice == "2":
            AuditEngine("192.168.56.101").run_full_audit()
            
        elif choice == "3":
            ip = Prompt.ask("IP objetivo")
            AuditEngine(ip).run_full_audit()
            
        elif choice == "4":
            ip = Prompt.ask("IP para Nmap", default="192.168.56.101")
            from services.nmap_scanner import NmapScanner
            host = NmapScanner(ip).full_scan()
            rprint(f"[green]✅ {len(host.ports_open)} puertos en {ip}[/green]")
            
        else:  # WPScan solo
            ip = Prompt.ask("WordPress URL", default="http://192.168.56.101")
            cmd = f"wpscan --url {ip} --enumerate u,vp,ap --no-banner"
            subprocess.run(cmd.split())
        
        if Confirm.ask("Otra auditoría?", default=False):
            continue
        break

if __name__ == '__main__':
    try:
        main_menu()
    except KeyboardInterrupt:
        rprint("\n[blue]👋 ¡Hasta luego![/blue]")
