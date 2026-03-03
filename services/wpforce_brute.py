import subprocess
import re
from pathlib import Path
from config import Config
from models.host import Host
from models.vuln import Vulnerability, RiskLevel


class WPForceBrute:
    def __init__(self, host: Host):
        self.host = host
        self.wp_dir = Path(f"{Config.OUTPUT_BASE}/wpscan")
        self.wp_dir.mkdir(parents=True, exist_ok=True)

    def _parse_wpscan_users(self, output):
        """Extraer usuarios encontrados por WPScan"""
        users = []
        for match in re.findall(r'\[!\]\s*(?:Login|Username)\s*found:\s*(\S+)', output, re.IGNORECASE):
            users.append(match)
        # Formato alternativo WPScan
        for match in re.findall(r'\|\s*(\w+)\s*\|', output):
            if match.lower() not in ['name', 'id', 'login', 'slug', 'status']:
                users.append(match)
        return list(set(users))

    def _parse_brute_results(self, output):
        """Extraer credenciales del brute-force"""
        creds = []
        # Buscar formato: | user | password |
        for match in re.findall(r'SUCCESS.*?(\w+)\s*[:\|]\s*(\S+)', output, re.IGNORECASE):
            creds.append({'source': 'WPScan Brute-Force', 'user': match[0], 'password': match[1], 'hash': ''})
        # Formato alternativo
        for match in re.findall(r'Valid Combination.*?Username:\s*(\S+).*?Password:\s*(\S+)', output, re.IGNORECASE):
            creds.append({'source': 'WPScan Brute-Force', 'user': match[0], 'password': match[1], 'hash': ''})
        return creds

    def attack(self):
        vulns = []
        print("   🔓 WPScan (Enumeración + Brute-Force)...")

        for port, service in list(self.host.ports_open.items())[:5]:
            if 'http' not in service['service'].lower():
                continue

            for path in Config.WORDPRESS_PATHS:
                url = f"http://{self.host.ip}:{port}{path}"
                output_file = self.wp_dir / f"wpscan_{self.host.ip}_{port}_{path.replace('/', '_')}.txt"

                # PASO 1: Enumerar usuarios y vulnerabilidades
                print(f"   🔍 WPScan enumerar: {url}")

                cmd_enum = [
                    'wpscan', '--url', url,
                    '--enumerate', 'u,vp,ap',
                    '--no-banner', '--disable-tls-checks',
                    '--output', str(output_file)
                ]

                try:
                    result = subprocess.run(cmd_enum, capture_output=True, text=True, timeout=180)
                    full_output = result.stdout

                    if any(kw in full_output.lower() for kw in ['vulnerable', 'critical', 'high', 'users found', 'user(s) identified']):
                        vuln = Vulnerability(
                            name="🔴 WORDPRESS VULNERABILIDADES",
                            description=f"WPScan detectó vulnerabilidades: {url}",
                            port=port,
                            risk=RiskLevel.CRITICAL,
                            evidence_file=str(output_file),
                            recommendations="Actualizar WordPress + Plugins, WAF, deshabilitar XML-RPC"
                        )
                        vulns.append(vuln)
                        print(f"   💥 Vulnerabilidades WordPress encontradas!")

                    # Extraer usuarios
                    users = self._parse_wpscan_users(full_output)
                    if users:
                        print(f"   👥 Usuarios encontrados: {', '.join(users)}")

                    # PASO 2: Brute-Force con diccionario
                    wordlist = Config.WORDLIST_PATH
                    if Path(wordlist).exists():
                        brute_output = self.wp_dir / f"brute_{self.host.ip}_{port}.txt"
                        print(f"   🔐 Brute-force con rockyou.txt...")

                        cmd_brute = [
                            'wpscan', '--url', url,
                            '--enumerate', 'u',
                            '--passwords', wordlist,
                            '--max-threads', '10',
                            '--no-banner', '--disable-tls-checks',
                            '--output', str(brute_output)
                        ]

                        try:
                            brute_result = subprocess.run(cmd_brute, capture_output=True, text=True, timeout=600)

                            creds = self._parse_brute_results(brute_result.stdout)
                            if creds:
                                self.host.credentials.extend(creds)
                                for c in creds:
                                    print(f"   🔑 CREDENCIAL: {c['user']} : {c['password']}")

                                vuln_brute = Vulnerability(
                                    name="🔴 WORDPRESS CONTRASEÑAS DÉBILES",
                                    description=f"Brute-force exitoso: {len(creds)} credenciales obtenidas",
                                    port=port,
                                    risk=RiskLevel.CRITICAL,
                                    evidence_file=str(brute_output),
                                    recommendations="Contraseñas robustas, limitar intentos login, 2FA"
                                )
                                vulns.append(vuln_brute)
                        except subprocess.TimeoutExpired:
                            print(f"   ⏰ Brute-force timeout (10min)")
                        except Exception:
                            pass
                    else:
                        print(f"   ⚠️ Wordlist no encontrada: {wordlist}")

                except subprocess.TimeoutExpired:
                    print(f"   ⏭️ WPScan timeout en {url}")
                except Exception as e:
                    print(f"   ⚠️ Error WPScan: {e}")

        return vulns
