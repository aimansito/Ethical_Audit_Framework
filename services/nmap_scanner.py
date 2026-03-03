import nmap
from pathlib import Path
from config import Config
from models.host import Host


class NmapScanner:
    def __init__(self, target_ip):
        self.target_ip = target_ip
        self.output_dir = Path(f"{Config.OUTPUT_BASE}/nmap")
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def full_scan(self):
        nm = nmap.PortScanner()
        print("   📡 Nmap Top 1000 + Servicios...")

        nm.scan(self.target_ip, '1-1000', arguments='-sV -sC --top-ports 1000')

        host = Host(ip=self.target_ip)
        if self.target_ip in nm.all_hosts():
            for proto in nm[self.target_ip].all_protocols():
                ports = nm[self.target_ip][proto].keys()
                for port in ports:
                    service = nm[self.target_ip][proto][port]
                    host.ports_open[int(port)] = {
                        'state': service['state'],
                        'service': service.get('name', 'unknown'),
                        'version': service.get('version', '')
                    }

        print(f"   ✅ {len(host.ports_open)} servicios detectados")
        return host
