from pathlib import Path


class Config:
    OUTPUT_BASE = Path("outputs")
    OUTPUT_BASE.mkdir(parents=True, exist_ok=True)

    WORDPRESS_PATHS = ['/', '/wp-admin/', '/wordpress/', '/wp-login.php']
    SQL_ENDPOINTS = ['/?id=1', '/search.php?q=1', '/page.php?id=1', '/user.php?id=1']
