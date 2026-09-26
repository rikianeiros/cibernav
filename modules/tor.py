"""
Salida por Tor (anonimato del tráfico saliente).

Cuando el modo Tor está activo:
  · las peticiones HTTP que hace la propia app (crt.sh, feed de CVEs, verificación
    de IP) salen por el SOCKS5 de Tor (127.0.0.1:9050) usando curl --socks5-hostname
    (la resolución DNS también va por Tor, evitando fugas);
  · las herramientas externas de recon se envuelven con torsocks/proxychains;
  · nmap pasa a connect scan (-sT), lo único torificable.

Qué NO se anonimiza (y la interfaz lo deja claro):
  · la parte Wi-Fi (es radio, no tráfico IP) — para eso se cambia la MAC;
  · el escaneo de la red local y NMEA (el objetivo está en la LAN);
  · las consultas DNS por UDP (dig) — Tor solo transporta TCP.
"""
import os
import json
import socket
import shutil
import subprocess

SOCKS_HOST = os.environ.get("CIBERNAV_TOR_HOST", "127.0.0.1")
SOCKS_PORT = int(os.environ.get("CIBERNAV_TOR_PORT", "9050"))


class TorState:
    def __init__(self):
        self.enabled = os.environ.get("CIBERNAV_TOR", "").lower() in ("1", "true", "yes", "si", "sí")


state = TorState()


def socks_available() -> bool:
    """¿Responde el puerto SOCKS de Tor localmente?"""
    try:
        with socket.create_connection((SOCKS_HOST, SOCKS_PORT), timeout=2):
            return True
    except Exception:
        return False


def _torify_prefix() -> list[str] | None:
    if shutil.which("torsocks"):
        return ["torsocks"]
    if shutil.which("proxychains4"):
        return ["proxychains4", "-q"]
    if shutil.which("proxychains"):
        return ["proxychains", "-q"]
    return None


def torify_cmd(cmd: list[str]) -> list[str]:
    """Antepone torsocks/proxychains al comando si el modo Tor está activo."""
    if not state.enabled:
        return cmd
    pref = _torify_prefix()
    return (pref + cmd) if pref else cmd


def http_get(url: str, timeout: int = 20) -> str:
    """
    GET de una URL. Con Tor activo sale por el SOCKS5 (curl --socks5-hostname,
    que además resuelve el DNS a través de Tor). Sin Tor, urllib directo.
    """
    if state.enabled:
        if not shutil.which("curl"):
            raise RuntimeError("Se necesita 'curl' para salir por Tor.")
        p = subprocess.run(
            ["curl", "-s", "--max-time", str(timeout),
             "--socks5-hostname", f"{SOCKS_HOST}:{SOCKS_PORT}", url],
            capture_output=True, text=True, timeout=timeout + 5,
        )
        if p.returncode != 0:
            raise RuntimeError(f"curl/tor error ({p.returncode}): {p.stderr.strip()[:200]}")
        return p.stdout
    import urllib.request
    req = urllib.request.Request(url, headers={"User-Agent": "CIBERNAV"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", errors="ignore")


def exit_ip(timeout: int = 20) -> dict:
    """IP de salida vista desde Internet, y si Tor la reconoce como nodo suyo."""
    try:
        data = http_get("https://check.torproject.org/api/ip", timeout)
        j = json.loads(data)
        return {"ip": j.get("IP"), "is_tor": bool(j.get("IsTor"))}
    except Exception as e:  # noqa: BLE001
        return {"error": str(e)}


def status(check_ip: bool = False) -> dict:
    s = {
        "enabled": state.enabled,
        "socks_ok": socks_available(),
        "torify": bool(_torify_prefix()),
        "socks": f"{SOCKS_HOST}:{SOCKS_PORT}",
    }
    if check_ip and state.enabled:
        s["exit"] = exit_ip()
    return s
