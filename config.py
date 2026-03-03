from pathlib import Path


class Config:
    OUTPUT_BASE = Path("outputs")
    OUTPUT_BASE.mkdir(parents=True, exist_ok=True)

    # Target por defecto
    DEFAULT_TARGET = '192.168.56.102'

    # DVWA
    DVWA_LOGIN_URL = '/dvwa/login.php'
    DVWA_SQLI_URL = '/dvwa/vulnerabilities/sqli/'
    DVWA_DEFAULT_USER = 'admin'
    DVWA_DEFAULT_PASS = 'password'

    # WordPress paths
    WORDPRESS_PATHS = ['/wordpress/', '/wp-login.php']

    # SQLMap endpoints genéricos (fallback)
    SQL_ENDPOINTS = ['/?id=1', '/search.php?q=1', '/page.php?id=1']

    # Wordlist para brute-force
    WORDLIST_PATH = '/usr/share/wordlists/rockyou.txt'
