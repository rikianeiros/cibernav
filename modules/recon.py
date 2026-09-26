"""
Reconocimiento web (OSINT + fase activa).

Dos fases:
  · PASIVA  -> no toca el objetivo, solo fuentes públicas (whois, DNS, crt.sh,
               whatweb, wafw00f, análisis SSL).
  · ACTIVA  -> interactúa con el servidor (nmap NSE http, nikto, gobuster,
               wpscan) y cruce con exploits (searchsploit). Requiere autorización
               y se bloquea en modo pasivo global.

SEGURIDAD: el dominio se valida con una regex estricta y TODOS los comandos se
ejecutan con lista de argumentos (nunca shell=True), de modo que no es posible
inyectar comandos a través del dominio.
"""
import re
import shutil
import json
import subprocess
import urllib.request

# Dominio válido (sin esquema, sin barras, sin espacios).
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)([a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,}$")


def valid_domain(d: str) -> bool:
    return bool(DOMAIN_RE.match((d or "").strip()))


def _run(cmd: list[str], timeout: int = 60) -> dict:
    """Ejecuta una herramienta si existe; devuelve salida acotada y estado."""
    tool = cmd[0]
    if not shutil.which(tool):
        return {"herramienta": tool, "disponible": False, "salida": "", "error": f"{tool} no está instalado"}
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        salida = (p.stdout + ("\n" + p.stderr if p.stderr else ""))[-8000:]
        return {"herramienta": tool, "disponible": True, "salida": salida.strip(), "error": None}
    except subprocess.TimeoutExpired:
        return {"herramienta": tool, "disponible": True, "salida": "", "error": "timeout"}
    except Exception as e:  # noqa: BLE001
        return {"herramienta": tool, "disponible": True, "salida": "", "error": str(e)}


# ---------------- FASE PASIVA ----------------

def whois_lookup(domain: str) -> dict:
    r = _run(["whois", domain], 25)
    m_reg = re.search(r"(?im)^\s*Registrar:\s*(.+)$", r["salida"])
    m_cre = re.search(r"(?im)^\s*Creation Date:\s*(.+)$", r["salida"])
    r["resumen"] = "; ".join(x.group(1).strip() for x in (m_reg, m_cre) if x) or "datos whois obtenidos" if r["salida"] else "sin datos"
    return r


def dns_records(domain: str) -> dict:
    """Registros DNS con dig; si no está, resuelve la A por socket."""
    if shutil.which("dig"):
        out = {}
        for tipo in ("A", "AAAA", "MX", "NS", "TXT"):
            r = _run(["dig", "+short", domain, tipo], 15)
            vals = [l for l in r["salida"].splitlines() if l.strip()]
            if vals:
                out[tipo] = vals
        return {"herramienta": "dig", "disponible": True, "registros": out,
                "resumen": ", ".join(f"{k}:{len(v)}" for k, v in out.items()) or "sin registros"}
    # Fallback sin dig
    import socket
    try:
        ip = socket.gethostbyname(domain)
        return {"herramienta": "socket", "disponible": True, "registros": {"A": [ip]}, "resumen": f"A:{ip}"}
    except Exception as e:  # noqa: BLE001
        return {"herramienta": "socket", "disponible": True, "registros": {}, "error": str(e), "resumen": "no resuelve"}


def subdomains_crtsh(domain: str, timeout: int = 20) -> dict:
    """Subdominios a partir de Certificate Transparency (crt.sh). Solo lectura."""
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "CIBERNAV"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            datos = json.loads(resp.read(3_000_000).decode("utf-8", errors="ignore"))
    except Exception as e:  # noqa: BLE001
        return {"herramienta": "crt.sh", "disponible": True, "subdominios": [], "error": str(e), "resumen": "sin datos"}
    subs = set()
    for entrada in datos if isinstance(datos, list) else []:
        for nombre in str(entrada.get("name_value", "")).splitlines():
            nombre = nombre.strip().lstrip("*.").lower()
            if nombre.endswith(domain) and valid_domain(nombre):
                subs.add(nombre)
    orden = sorted(subs)
    return {"herramienta": "crt.sh", "disponible": True, "subdominios": orden, "resumen": f"{len(orden)} subdominios"}


def whatweb(domain: str) -> dict:
    r = _run(["whatweb", "--no-errors", "-a", "1", f"https://{domain}"], 40)
    r["resumen"] = (r["salida"].splitlines() or ["sin datos"])[0][:200] if r["salida"] else "sin datos"
    return r


def wafwoof(domain: str) -> dict:
    r = _run(["wafw00f", f"https://{domain}"], 40)
    m = re.search(r"is behind (.+)", r["salida"] or "")
    r["resumen"] = m.group(1).strip() if m else ("sin WAF detectado" if r["salida"] else "sin datos")
    return r


def ssl_scan(domain: str) -> dict:
    r = _run(["sslscan", "--no-colour", domain], 45)
    debiles = re.findall(r"(?i)(SSLv[23]|TLSv1\.0|RC4|MD5|EXPORT|NULL)", r["salida"] or "")
    r["resumen"] = f"{len(set(debiles))} indicios de configuración débil" if debiles else ("TLS revisado" if r["salida"] else "sin datos")
    return r


def recon_pasivo(domain: str) -> dict:
    return {
        "dominio": domain,
        "whois": whois_lookup(domain),
        "dns": dns_records(domain),
        "subdominios": subdomains_crtsh(domain),
        "whatweb": whatweb(domain),
        "waf": wafwoof(domain),
        "ssl": ssl_scan(domain),
    }


# ---------------- FASE ACTIVA ----------------

def nmap_web(domain: str) -> dict:
    r = _run(["nmap", "-sV", "-p", "80,443,8080,8443", "--script", "http-enum,http-headers,http-title", domain], 150)
    r["resumen"] = f"{len(re.findall(r'/[a-z]', r['salida'] or ''))} rutas/cabeceras" if r["salida"] else "sin datos"
    return r


def nikto(domain: str) -> dict:
    r = _run(["nikto", "-h", f"https://{domain}", "-maxtime", "120s", "-nointeractive"], 140)
    r["resumen"] = f"{r['salida'].count('+ ')} observaciones" if r["salida"] else "sin datos"
    return r


def gobuster(domain: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt") -> dict:
    if not shutil.which("gobuster"):
        return {"herramienta": "gobuster", "disponible": False, "salida": "", "error": "gobuster no está instalado"}
    if not _existe(wordlist):
        return {"herramienta": "gobuster", "disponible": True, "salida": "", "error": f"diccionario no encontrado: {wordlist}"}
    r = _run(["gobuster", "dir", "-q", "-u", f"https://{domain}", "-w", wordlist, "-t", "20"], 150)
    r["resumen"] = f"{len([l for l in (r['salida'] or '').splitlines() if l.strip()])} rutas encontradas"
    return r


def wpscan(domain: str) -> dict:
    r = _run(["wpscan", "--url", f"https://{domain}", "--no-banner", "--random-user-agent",
              "--enumerate", "vp,u", "--format", "cli-no-color"], 180)
    r["resumen"] = f"{(r['salida'] or '').count('[!]')} avisos" if r["salida"] else "sin datos"
    return r


def searchsploit(termino: str) -> dict:
    r = _run(["searchsploit", "--color=never", termino], 30)
    n = len([l for l in (r["salida"] or "").splitlines() if "|" in l]) - 1
    r["resumen"] = f"{max(n, 0)} exploits en Exploit-DB" if r["salida"] else "sin resultados"
    return r


def recon_activo(domain: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt", con_wpscan: bool = True) -> dict:
    res = {
        "dominio": domain,
        "nmap_web": nmap_web(domain),
        "nikto": nikto(domain),
        "gobuster": gobuster(domain, wordlist),
    }
    if con_wpscan:
        res["wpscan"] = wpscan(domain)
    return res


def _existe(path: str) -> bool:
    import os
    return os.path.isfile(path)


# ---------------- capacidades ----------------

RECON_TOOLS = ["whois", "dig", "whatweb", "wafw00f", "sslscan", "nikto", "gobuster", "wpscan", "searchsploit"]


def herramientas_disponibles() -> dict:
    return {t: shutil.which(t) is not None for t in RECON_TOOLS}
