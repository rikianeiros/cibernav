"""
Base de conocimiento de vulnerabilidades conocidas, ACTUALIZABLE.

NO es un escáner de vulnerabilidades completo ni sustituye al NVD: es un conjunto
de reglas que identifican casos muy conocidos por el banner de servicio/versión
que devuelve nmap.

Las reglas viven en un fichero JSON editable (data/cve_rules.json), de modo que
se pueden actualizar sin tocar el código:

  · a mano, editando el JSON;
  · desde un feed remoto, con update_from_url() (endpoint POST /api/vulns/update);
  · recargando en caliente con reload_rules() (POST /api/vulns/reload).

Formato de cada regla (mismos campos que el 'seed' de abajo):
  {"match": "vsftpd", "versions": ["2.3.4"], "cve": "...", "severidad": "...", "descripcion": "..."}
  match       -> subcadena que debe aparecer en 'servicio + banner' (obligatorio)
  versions    -> lista de versiones exactas; [""] = cualquier versión (opcional)
  version_lt  -> casa si la versión detectada es menor que esta (opcional)
  version_gte -> casa si la versión detectada es mayor o igual que esta (opcional)
"""
import re
import os
import json
import time
import urllib.request

from config import BASE_DIR

RULES_FILE = os.environ.get("CIBERNAV_CVE_FILE", os.path.join(BASE_DIR, "data", "cve_rules.json"))
CVE_FEED = os.environ.get("CIBERNAV_CVE_FEED", "")

# Reglas de arranque: se escriben en el JSON la primera vez si no existe.
SEED_RULES = [
    {"match": "vsftpd", "versions": ["2.3.4"], "cve": "CVE-2011-2523", "severidad": "CRÍTICO",
     "descripcion": "Backdoor en vsftpd 2.3.4: un usuario acabado en ':)' abre una shell en el puerto 6200."},
    {"match": "proftpd", "versions": ["1.3.5"], "cve": "CVE-2015-3306", "severidad": "CRÍTICO",
     "descripcion": "mod_copy en ProFTPD 1.3.5 permite copiar archivos sin autenticar (RCE)."},
    {"match": "unrealircd", "versions": ["3.2.8.1"], "cve": "CVE-2010-2075", "severidad": "CRÍTICO",
     "descripcion": "UnrealIRCd 3.2.8.1 distribuido con un backdoor que permite ejecución remota."},
    {"match": "openssh", "version_lt": "7.7", "cve": "CVE-2018-15473", "severidad": "MEDIO",
     "descripcion": "OpenSSH < 7.7: enumeración de usuarios válidos por diferencia de tiempo de respuesta."},
    {"match": "apache", "versions": ["2.4.49"], "cve": "CVE-2021-41773", "severidad": "CRÍTICO",
     "descripcion": "Apache httpd 2.4.49: path traversal que puede derivar en RCE."},
    {"match": "apache", "versions": ["2.4.50"], "cve": "CVE-2021-42013", "severidad": "CRÍTICO",
     "descripcion": "Apache httpd 2.4.50: bypass del parche anterior, path traversal / RCE."},
    {"match": "samba", "version_gte": "3.5.0", "version_lt": "4.6.4", "cve": "CVE-2017-7494 (SambaCry)", "severidad": "CRÍTICO",
     "descripcion": "Samba 3.5.0–4.6.3: ejecución remota subiendo una librería a un recurso escribible."},
    {"match": "exim", "version_gte": "4.87", "version_lt": "4.92", "cve": "CVE-2019-10149", "severidad": "CRÍTICO",
     "descripcion": "Exim 4.87–4.91: ejecución remota de comandos como root vía dirección de destinatario."},
    {"match": "microsoft-ds", "versions": [""], "cve": "MS17-010 (EternalBlue)", "severidad": "CRÍTICO",
     "descripcion": "SMBv1 sin parchear es vulnerable a EternalBlue (RCE). Verifica el parche MS17-010."},
]

_rules: list[dict] = []
_meta = {"origen": None, "actualizado": None, "n": 0}


def _valida(reglas) -> list[dict]:
    """Se queda solo con reglas bien formadas (con 'match', 'cve' y 'descripcion')."""
    if not isinstance(reglas, list):
        raise ValueError("El conjunto de reglas debe ser una lista JSON.")
    ok = []
    for r in reglas:
        if isinstance(r, dict) and r.get("match") and r.get("cve") and r.get("descripcion"):
            r.setdefault("severidad", "DESCONOCIDO")
            ok.append(r)
    return ok


def load_rules() -> int:
    """Carga las reglas del JSON. Si no existe, lo crea con el seed."""
    global _rules
    try:
        if not os.path.isfile(RULES_FILE):
            os.makedirs(os.path.dirname(RULES_FILE), exist_ok=True)
            with open(RULES_FILE, "w", encoding="utf-8") as f:
                json.dump(SEED_RULES, f, ensure_ascii=False, indent=2)
            _rules = list(SEED_RULES)
            _meta.update(origen=f"seed -> {RULES_FILE}", actualizado=time.strftime("%Y-%m-%d %H:%M"))
        else:
            with open(RULES_FILE, encoding="utf-8") as f:
                _rules = _valida(json.load(f))
            _meta.update(origen=RULES_FILE, actualizado=time.strftime("%Y-%m-%d %H:%M",
                        time.localtime(os.path.getmtime(RULES_FILE))))
    except Exception:
        # Si el fichero está corrupto, no dejamos la app sin reglas.
        _rules = list(SEED_RULES)
        _meta.update(origen="seed (fallback)", actualizado=None)
    _meta["n"] = len(_rules)
    return len(_rules)


def reload_rules() -> dict:
    load_rules()
    return dict(_meta)


def update_from_url(url: str = "", timeout: int = 15, merge: bool = True) -> dict:
    """
    Descarga un conjunto de reglas en JSON desde `url` (o el feed configurado en
    CIBERNAV_CVE_FEED), lo valida y lo guarda. Por defecto FUSIONA con las reglas
    actuales (sin duplicar por CVE); con merge=False, las reemplaza.
    """
    url = url or CVE_FEED
    if not url:
        return {"error": "No se ha indicado ninguna URL de feed (ni CIBERNAV_CVE_FEED)."}
    try:
        from modules import tor
        datos = tor.http_get(url, timeout)[:2_000_000]  # sale por Tor si está activo
        nuevas = _valida(json.loads(datos))
    except Exception as e:
        return {"error": f"No se pudo actualizar desde {url}: {e}"}

    if merge:
        por_cve = {r["cve"]: r for r in _rules}
        for r in nuevas:
            por_cve[r["cve"]] = r
        combinadas = list(por_cve.values())
    else:
        combinadas = nuevas

    try:
        os.makedirs(os.path.dirname(RULES_FILE), exist_ok=True)
        with open(RULES_FILE, "w", encoding="utf-8") as f:
            json.dump(combinadas, f, ensure_ascii=False, indent=2)
    except OSError as e:
        return {"error": f"No se pudo guardar el fichero de reglas: {e}"}

    load_rules()
    return {"ok": True, "origen": url, "reglas": len(_rules), "nuevas": len(nuevas)}


def info() -> dict:
    return dict(_meta)


def _vtuple(v: str):
    nums = re.findall(r"\d+", v or "")
    return tuple(int(n) for n in nums) if nums else ()


def _extraer_version(banner: str) -> str:
    m = re.search(r"\d+(?:\.\d+)+", banner or "")
    return m.group(0) if m else ""


_VULNERS_LINE = re.compile(r"(CVE-\d{4}-\d+|[A-Z0-9]+:[A-Z0-9-]+)\s+(\d+\.\d+)")


def parse_vulners(texto: str) -> list[dict]:
    """
    Parsea la salida del script NSE `vulners` de nmap. Devuelve una lista de
    {cve, cvss, severidad} ordenada por CVSS descendente, sin duplicados.
    """
    vistos = {}
    for m in _VULNERS_LINE.finditer(texto or ""):
        ident, score = m.group(1), float(m.group(2))
        if ident not in vistos or score > vistos[ident]:
            vistos[ident] = score
    salida = []
    for ident, score in sorted(vistos.items(), key=lambda x: -x[1]):
        if score >= 9.0:
            sev = "CRÍTICO"
        elif score >= 7.0:
            sev = "ALTO"
        elif score >= 4.0:
            sev = "MEDIO"
        else:
            sev = "BAJO"
        salida.append({"cve": ident, "cvss": score, "severidad": sev})
    return salida


def match_cves(service: str, version_banner: str) -> list[dict]:
    """CVEs conocidos que casan con el servicio y su versión detectada."""
    texto = f"{service} {version_banner}".lower()
    ver = _extraer_version(version_banner)
    vt = _vtuple(ver)
    encontrados = []
    for r in _rules:
        if r["match"].lower() not in texto:
            continue
        if "versions" in r:
            if r["versions"] != [""] and ver not in r["versions"]:
                continue
        if "version_lt" in r and (not vt or vt >= _vtuple(r["version_lt"])):
            continue
        if "version_gte" in r and (not vt or vt < _vtuple(r["version_gte"])):
            continue
        encontrados.append({"cve": r["cve"], "severidad": r.get("severidad", "DESCONOCIDO"),
                            "descripcion": r["descripcion"]})
    return encontrados


# Cargar al importar
load_rules()
