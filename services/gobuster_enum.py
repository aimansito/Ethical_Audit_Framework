import subprocess
import re
from pathlib import Path
from config import Config
from rich import print as rprint


class GobusterEnum:
    """Enumeración de directorios con Gobuster/Dirb"""

    def __init__(self, host):
        self.host = host
        self.dir_output = Path(f"{Config.OUTPUT_BASE}/gobuster")
        self.dir_output.mkdir(parents=True, exist_ok=True)

    def enumerate(self):
        """Enumerar directorios en todos los puertos HTTP"""
        all_dirs = []
        
        for port, service in self.host.ports_open.items():
            if 'http' not in service['service'].lower():
                continue

            url = f"http://{self.host.ip}:{port}/"
            output_file = self.dir_output / f"dirs_{self.host.ip}_{port}.txt"

            rprint(f"   [cyan]🔎 Gobuster: {url}[/cyan]")

            # Intentar gobuster primero, si no existe usar dirb
            dirs = self._run_gobuster(url, output_file)
            if not dirs:
                dirs = self._run_dirb(url, output_file)

            all_dirs.extend(dirs)

            for d in dirs:
                status = d.get('status', '???')
                path = d.get('path', '')
                if status in ['200', '301', '302', '403']:
                    color = 'green' if status == '200' else 'yellow' if status in ['301','302'] else 'red'
                    rprint(f"   [{color}][+] {path} (Status: {status})[/{color}]")

        return all_dirs

    def _run_gobuster(self, url, output_file):
        """Ejecutar gobuster dir"""
        dirs = []
        wordlist = Config.GOBUSTER_WORDLIST

        if not Path(wordlist).exists():
            return []

        cmd = [
            'gobuster', 'dir',
            '-u', url,
            '-w', wordlist,
            '-t', '20',
            '-q',
            '--no-error',
            '-o', str(output_file)
        ]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            output = result.stdout

            # Parsear resultados: /path (Status: 200)
            for match in re.findall(r'(/\S+)\s+\(Status:\s*(\d+)\)', output):
                dirs.append({'path': match[0], 'status': match[1]})

            # Formato alternativo
            for match in re.findall(r'(/\S+)\s+\[Status=(\d+)', output):
                dirs.append({'path': match[0], 'status': match[1]})

        except FileNotFoundError:
            pass  # gobuster no instalado
        except subprocess.TimeoutExpired:
            rprint("   [yellow]⏰ Gobuster timeout[/yellow]")
        except Exception:
            pass

        return dirs

    def _run_dirb(self, url, output_file):
        """Fallback: usar dirb si gobuster no está"""
        dirs = []
        wordlist = Config.GOBUSTER_WORDLIST

        if not Path(wordlist).exists():
            return []

        cmd = ['dirb', url, wordlist, '-S', '-N', '404']

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

            for match in re.findall(r'\+\s+(http\S+)\s+\(CODE:(\d+)', result.stdout):
                path = match[0].replace(url.rstrip('/'), '')
                dirs.append({'path': path or '/', 'status': match[1]})

        except FileNotFoundError:
            rprint("   [yellow]⚠️ Ni gobuster ni dirb instalados[/yellow]")
        except subprocess.TimeoutExpired:
            rprint("   [yellow]⏰ Dirb timeout[/yellow]")
        except Exception:
            pass

        return dirs
