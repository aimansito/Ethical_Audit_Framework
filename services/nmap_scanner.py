import nmap
from pathlib import Path
from config import Config
from models.host import Host
from rich import print as rprint


class NmapScanner:
    def __init__(self, target_ip):
        self.target_ip = target_ip
        self.output_dir = Path(f"{Config.OUTPUT_BASE}/nmap")
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def full_scan(self):
        nm = nmap.PortScanner()
        rprint(f"   [cyan]📡 Nmap Top 1000 + Servicios + OS Detection...[/cyan]")

        nm.scan(self.target_ip, '1-1000', arguments='-sV -sC -O --top-ports 1000')

        host = Host(ip=self.target_ip)

        if self.target_ip in nm.all_hosts():
            # OS Detection
            try:
                os_matches = nm[self.target_ip].get('osmatch', [])
                if os_matches:
                    best = os_matches[0]
                    host.os_detection = f"{best.get('name', 'Unknown')} ({best.get('accuracy', '?')}%)"
                    rprint(f"   [green]🖥️  OS Detectado: {host.os_detection}[/green]")
                else:
                    # Intentar osclass
                    os_class = nm[self.target_ip].get('osclass', [])
                    if os_class:
                        oc = os_class[0]
                        host.os_detection = f"{oc.get('osfamily', '')} {oc.get('osgen', '')}"
                        rprint(f"   [green]🖥️  OS Detectado: {host.os_detection}[/green]")
            except Exception:
                pass

            # Puertos
            for proto in nm[self.target_ip].all_protocols():
                ports = nm[self.target_ip][proto].keys()
                for port in ports:
                    service = nm[self.target_ip][proto][port]
                    host.ports_open[int(port)] = {
                        'state': service['state'],
                        'service': service.get('name', 'unknown'),
                        'version': service.get('version', ''),
                        'product': service.get('product', ''),
                        'extra': service.get('extrainfo', '')
                    }

        rprint(f"   [green]✅ {len(host.ports_open)} servicios detectados[/green]")

        # Tabla detallada
        if host.ports_open:
            rprint(f"\n   [bold]{'PORT':<12} {'STATE':<10} {'SERVICE':<15} {'VERSION'}[/bold]")
            rprint(f"   {'─'*60}")
            for port, info in sorted(host.ports_open.items()):
                state = info['state']
                svc = info['service']
                ver = f"{info.get('product','')} {info['version']}".strip()
                color = 'green' if state == 'open' else 'yellow'
                rprint(f"   [{color}]{port}/tcp{'':<6} {state:<10} {svc:<15} {ver}[/{color}]")

        return host

    @staticmethod
    def discover_network(network='192.168.56.0/24'):
        """Auto-descubrir hosts en la red"""
        import subprocess
        hosts = []

        rprint(f"\n[bold cyan]{'='*60}[/bold cyan]")
        rprint(f"[bold cyan]🔍 NETWORK DISCOVERY: {network}[/bold cyan]")
        rprint(f"[bold cyan]{'='*60}[/bold cyan]\n")

        try:
            result = subprocess.run(
                ['nmap', '-sn', network],
                capture_output=True, text=True, timeout=30
            )

            for line in result.stdout.split('\n'):
                if 'Nmap scan report for' in line:
                    parts = line.split()
                    ip = parts[-1].strip('()')
                    if ip.startswith('192.168.56.') and not ip.endswith('.1') and not ip.endswith('.0'):
                        hosts.append(ip)

            rprint(f"[green]   ✅ {len(hosts)} host(s) encontrados en {network}[/green]")
            for h in hosts:
                rprint(f"   [cyan]📌 {h}[/cyan]")

        except Exception as e:
            rprint(f"[red]   ❌ Error en discovery: {e}[/red]")
            hosts = [Config.DEFAULT_TARGET]

        return hosts
