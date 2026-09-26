"""
Detección de capacidades del entorno.

CIBERNAV está pensado para degradar con elegancia: en un equipo sin las
herramientas de Kali (por ejemplo un Mac de desarrollo, o Kali en una VM
sin la antena USB en modo monitor) las funciones de análisis pasivo
—nmap, NMEA, informes— siguen disponibles, y solo se desactiva lo que
depende del hardware o de las herramientas ausentes.
"""
import shutil
import subprocess

# Herramientas necesarias por cada capacidad.
_TOOLS = {
    "wifi_scan": ["airodump-ng", "airmon-ng"],
    "wifi_attack": ["aireplay-ng"],
    "pmkid": ["hcxdumptool"],
    "nmap": ["nmap"],
    "bettercap": ["bettercap"],
    "cracking": ["aircrack-ng", "hashcat"],
}


def _tool_available(tool: str) -> bool:
    return shutil.which(tool) is not None


def list_monitor_interfaces() -> list[str]:
    """Interfaces de red inalámbrica detectadas (via iwconfig si existe)."""
    if not _tool_available("iwconfig"):
        return []
    try:
        out = subprocess.run(["iwconfig"], capture_output=True, text=True, timeout=5).stdout
    except Exception:
        return []
    return [line.split(" ")[0] for line in out.splitlines() if "IEEE" in line and line and not line.startswith(" ")]


def report_pdf_available() -> bool:
    try:
        import weasyprint  # noqa: F401
        return True
    except Exception:
        return False


def get_capabilities() -> dict:
    """
    Devuelve el estado de cada capacidad y una lista de avisos legibles
    para mostrar en la interfaz. Nunca lanza excepción.
    """
    caps = {}
    for cap, tools in _TOOLS.items():
        missing = [t for t in tools if not _tool_available(t)]
        caps[cap] = {"available": not missing, "missing_tools": missing}

    wifi_ifaces = list_monitor_interfaces()
    caps["wifi_scan"]["interfaces"] = wifi_ifaces
    caps["report"] = {"available": report_pdf_available(), "missing_tools": [] if report_pdf_available() else ["weasyprint"]}

    warnings = []
    if not caps["wifi_scan"]["available"]:
        warnings.append("Herramientas Wi-Fi no encontradas: el reconocimiento y los ataques inalámbricos están desactivados. El resto (nmap, NMEA, informes) sigue disponible.")
    elif not wifi_ifaces:
        warnings.append("No se detecta ninguna interfaz inalámbrica. Conecta una antena compatible con modo monitor (p. ej. Alfa AWUS036ACH) para escanear Wi-Fi.")
    if not caps["nmap"]["available"]:
        warnings.append("nmap no está instalado: el escaneo de puertos está desactivado (apt install nmap).")
    if not caps["report"]["available"]:
        warnings.append("WeasyPrint no disponible: los informes se mostrarán en HTML en lugar de PDF.")

    # Diccionario para el crackeo
    import os as _os
    from config import DEFAULT_WORDLIST
    wl_ok = _os.path.isfile(DEFAULT_WORDLIST)
    caps["wordlist"] = {"available": wl_ok, "path": DEFAULT_WORDLIST, "missing_tools": [] if wl_ok else [DEFAULT_WORDLIST]}
    if caps["cracking"]["available"] and not wl_ok:
        warnings.append(f"No se encuentra el diccionario ({DEFAULT_WORDLIST}). En Kali suele venir comprimido: gunzip /usr/share/wordlists/rockyou.txt.gz")

    return {"capabilities": caps, "warnings": warnings}
