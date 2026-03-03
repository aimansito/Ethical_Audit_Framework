import hashlib
from config import Config
from rich import print as rprint


class HashCracker:
    """Crackeo rápido de hashes MD5 con diccionario"""

    HASH_MD5_KNOWN = {
        '5f4dcc3b5aa765d61d8327deb882cf99': 'password',
        '21232f297a57a5a743894a0e4a801fc3': 'admin',
        '0192023a7bbd73250516f069df18b500': 'admin123',
        'e10adc3949ba59abbe56e057f20f883e': '123456',
        '63a9f0ea7bb98050796b649e85481845': 'root',
        '7813d1590d28a7dd372ad54b5d29571b': 'toor',
        '0d107d09f5bbe40cade3de5c71e9e9b7': 'letmein',
        '40be4e59b9a2a2b5dffb918c0e86b3d7': 'monkey',
        '8621ffdbc5698829397d97767ac13db3': 'dragon',
        'eb0a191797624dd3a48fa681d3061212': 'qwerty',
        'd8578edf8458ce06fbc5bb76a58c5ca4': 'qwerty',
    }

    @classmethod
    def crack_md5(cls, hash_value):
        """Intentar crackear un hash MD5"""
        hash_lower = hash_value.strip().lower()

        # 1. Buscar en hashes conocidos
        if hash_lower in cls.HASH_MD5_KNOWN:
            return cls.HASH_MD5_KNOWN[hash_lower]

        # 2. Probar contraseñas comunes
        for pwd in Config.COMMON_PASSWORDS:
            if hashlib.md5(pwd.encode()).hexdigest() == hash_lower:
                return pwd

        return None

    @classmethod
    def crack_credentials(cls, credentials):
        """Crackear todos los hashes en una lista de credenciales"""
        cracked = 0
        for cred in credentials:
            hash_val = cred.get('hash', '')
            # Si parece un hash MD5 (32 hex chars)
            if hash_val and len(hash_val) == 32 and all(c in '0123456789abcdefABCDEF' for c in hash_val):
                result = cls.crack_md5(hash_val)
                if result:
                    cred['password'] = f"{result}"
                    cred['cracked'] = True
                    cracked += 1
                    rprint(f"   [bold green]✅ CRACKED: {cred['user']} → {hash_val[:16]}... = '{result}'[/bold green]")
                else:
                    cred['cracked'] = False
                    rprint(f"   [yellow]❌ No crackeado: {cred['user']} → {hash_val[:16]}...[/yellow]")

        return cracked
