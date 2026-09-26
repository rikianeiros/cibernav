"""
Configuración central de CIBERNAV.

Las credenciales y rutas se leen de variables de entorno para no dejar
secretos en el código. Copia `.env.example` a `.env` y ajústalo, o
expórtalas en tu shell antes de arrancar.
"""
import os
import secrets

# --- Directorios ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.environ.get("CIBERNAV_DATA_DIR", "/tmp/cibernav")
TMP_DIR = DATA_DIR  # alias de compatibilidad con módulos heredados
CAPTURES_DIR = os.path.join(DATA_DIR, "captures")
FOUND_DIR = os.path.join(DATA_DIR, "found")
REPORTS_DIR = os.path.join(DATA_DIR, "reports")
DB_PATH = os.environ.get("CIBERNAV_DB_PATH", os.path.join(BASE_DIR, "db", "cibernav.db"))

for _d in (DATA_DIR, CAPTURES_DIR, FOUND_DIR, REPORTS_DIR, os.path.dirname(DB_PATH)):
    os.makedirs(_d, exist_ok=True)

# --- Rutas de escaneo (airodump) ---
SCAN_OUTPUT_PREFIX = os.path.join(DATA_DIR, "scan")
SCAN_CSV_PATH = f"{SCAN_OUTPUT_PREFIX}-01.csv"
SCAN_CAP_PATH = f"{SCAN_OUTPUT_PREFIX}-01.cap"

# --- Seguridad de la interfaz web ---
# Si no se define contraseña por entorno, se genera una aleatoria por sesión
# y se muestra por consola al arrancar. Nunca hay credenciales fijas en el repo.
WEB_AUTH_USER = os.environ.get("CIBERNAV_USER", "admin")
WEB_AUTH_PASS = os.environ.get("CIBERNAV_PASS") or secrets.token_urlsafe(12)
AUTH_PASS_IS_RANDOM = "CIBERNAV_PASS" not in os.environ

# --- Bettercap ---
BETTERCAP_API_URL = os.environ.get("BETTERCAP_API_URL", "http://127.0.0.1:8081")
BETTERCAP_API_USER = os.environ.get("BETTERCAP_API_USER", "cibernav")
BETTERCAP_API_PASS = os.environ.get("BETTERCAP_API_PASS", "")

# --- Parámetros de tiempo ---
POLL_INTERVAL_SEC = int(os.environ.get("CIBERNAV_POLL_INTERVAL", "2"))
HANDSHAKE_TIMEOUT = 120
NMAP_TIMEOUT = 300

# --- Diccionarios ---
DEFAULT_WORDLIST = os.environ.get("CIBERNAV_WORDLIST", "/usr/share/wordlists/rockyou.txt")

# --- Puertos NMEA (modo naval) ---
NMEA_PORTS = [10110, 2000]
