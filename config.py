from pathlib import Path


class Config:
    OUTPUT_BASE = Path("outputs")
    OUTPUT_BASE.mkdir(parents=True, exist_ok=True)

    # Target por defecto
    DEFAULT_TARGET = '192.168.56.102'
    DEFAULT_NETWORK = '192.168.56.0/24'

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

    # Gobuster
    GOBUSTER_WORDLIST = '/usr/share/wordlists/dirb/common.txt'

    # Hashes comunes para crackeo rápido
    COMMON_PASSWORDS = [
        'password', 'admin', 'admin123', '123456', 'root', 'toor',
        'letmein', 'welcome', 'monkey', 'dragon', 'master', 'qwerty',
        'login', 'abc123', 'starwars', 'trustno1', 'iloveyou', 'shadow',
        'superman', 'batman', '1234567890', 'password1', 'hello',
        'charlie', 'donald', 'football', 'michael', 'passwd'
    ]
