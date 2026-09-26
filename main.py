"""
CIBERNAV — Suite de auditoría de seguridad de redes (Wi-Fi / IoT / naval).

API FastAPI que unifica:
  · Reconocimiento Wi-Fi en tiempo real y ataques (deauth / handshake / PMKID)
  · Escaneo de puertos con nmap y traducción de riesgos
  · Modo naval: captura de datos NMEA en claro (PoC)
  · Persistencia por objetivo e informes (PDF/HTML)

Diseñada para degradar con elegancia: en un equipo sin las herramientas de
Kali o sin antena en modo monitor, las funciones de análisis pasivo siguen
disponibles y solo se desactiva lo que depende del hardware ausente.
"""
from fastapi import FastAPI, Depends, HTTPException, status, WebSocket, WebSocketDisconnect
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.requests import Request
import asyncio
import os
import subprocess
import secrets
import logging
from datetime import datetime

from config import (
    WEB_AUTH_USER, WEB_AUTH_PASS, AUTH_PASS_IS_RANDOM, BASE_DIR,
    POLL_INTERVAL_SEC, SCAN_OUTPUT_PREFIX, SCAN_CSV_PATH, NMEA_PORTS, PASSIVE_DEFAULT,
)
from modules.scanner import enable_monitor_mode, disable_monitor_mode, parse_airodump_csv
from modules.alert_engine import alert_engine
from modules.attacker import attack_manager
from modules.nmap_scanner import nmap_scanner
from modules.bettercap import bettercap_client
from modules import nmea, system_check, report
from modules.cracker import crack_manager
from modules.database import init_db, db_manager

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("cibernav")

app = FastAPI(title="CIBERNAV API")
security = HTTPBasic()

app.mount("/static", StaticFiles(directory=os.path.join(BASE_DIR, "static")), name="static")
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))


@app.on_event("startup")
def _startup():
    init_db()
    if AUTH_PASS_IS_RANDOM:
        logger.warning("=" * 60)
        logger.warning(" CIBERNAV: no se definió CIBERNAV_PASS.")
        logger.warning(" Credenciales de esta sesión -> usuario: %s  contraseña: %s", WEB_AUTH_USER, WEB_AUTH_PASS)
        logger.warning(" Define CIBERNAV_USER / CIBERNAV_PASS para fijarlas.")
        logger.warning("=" * 60)


# --- Autenticación ---
def verify_credentials(credentials: HTTPBasicCredentials = Depends(security)):
    ok_user = secrets.compare_digest(credentials.username, WEB_AUTH_USER)
    ok_pass = secrets.compare_digest(credentials.password, WEB_AUTH_PASS)
    if not (ok_user and ok_pass):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciales incorrectas",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials.username


# --- Estado ---
class AppState:
    def __init__(self):
        self.scanning = False
        self.scan_process = None
        self.interface = None
        self.monitor_interface = None
        self.networks = {}
        self.clients = {}
        self.passive = PASSIVE_DEFAULT


state = AppState()


def ensure_active():
    """Bloquea las acciones ofensivas cuando el modo pasivo está activo."""
    if state.passive:
        raise HTTPException(
            status_code=status.HTTP_423_LOCKED,
            detail="Modo pasivo activo: las acciones ofensivas (ataques y crackeo) están deshabilitadas.",
        )


class ConnectionManager:
    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        for connection in list(self.active_connections):
            try:
                await connection.send_json(message)
            except Exception:
                pass


manager = ConnectionManager()


# --- Tarea de fondo de escaneo Wi-Fi ---
async def scan_loop():
    while state.scanning:
        if os.path.exists(SCAN_CSV_PATH):
            networks, clients = parse_airodump_csv(SCAN_CSV_PATH)
            state.networks = networks
            state.clients = clients
            await manager.broadcast({
                "type": "scan_update",
                "networks": list(networks.values()),
                "clients": list(clients.values()),
                "alerts": alert_engine.alerts[-10:],
                "stats": {
                    "total_networks": len(networks),
                    "total_clients": len(clients),
                    "open_networks": len([n for n in networks.values() if "OPEN_NETWORK" in n.get("flags", [])]),
                    "wps_networks": len([n for n in networks.values() if "WPS_ENABLED" in n.get("flags", [])]),
                },
            })
        await asyncio.sleep(POLL_INTERVAL_SEC)


# --- Vistas ---
@app.get("/", response_class=HTMLResponse)
async def index(request: Request, username: str = Depends(verify_credentials)):
    return templates.TemplateResponse(request, "index.html")


@app.get("/api/capabilities")
async def capabilities(username: str = Depends(verify_credentials)):
    data = system_check.get_capabilities()
    data["passive"] = state.passive
    return data


@app.get("/api/mode")
async def get_mode(username: str = Depends(verify_credentials)):
    return {"passive": state.passive}


@app.post("/api/mode")
async def set_mode(passive: bool, username: str = Depends(verify_credentials)):
    state.passive = passive
    alert_engine.add_alert("INFO", f"Modo pasivo {'activado' if passive else 'desactivado'}", "system")
    return {"passive": state.passive}


# --- Wi-Fi ---
@app.get("/api/interfaces")
async def get_interfaces(username: str = Depends(verify_credentials)):
    return {"interfaces": system_check.list_monitor_interfaces()}


@app.post("/api/monitor/start")
async def start_monitor(interface: str, username: str = Depends(verify_credentials)):
    if state.monitor_interface:
        return {"status": "already_started", "interface": state.monitor_interface}
    state.interface = interface
    state.monitor_interface = enable_monitor_mode(interface)
    return {"status": "started", "interface": state.monitor_interface}


@app.post("/api/monitor/stop")
async def stop_monitor(username: str = Depends(verify_credentials)):
    if state.monitor_interface:
        disable_monitor_mode(state.monitor_interface)
        state.monitor_interface = None
        state.interface = None
    return {"status": "stopped"}


@app.post("/api/scan/start")
async def start_scan(username: str = Depends(verify_credentials)):
    if state.scanning or not state.monitor_interface:
        return {"error": "Escaneo ya iniciado o interfaz no configurada"}
    os.system(f"rm -f {SCAN_OUTPUT_PREFIX}*")
    cmd = ["sudo", "airodump-ng", "-w", SCAN_OUTPUT_PREFIX, "--output-format", "csv,pcap", state.monitor_interface]
    state.scan_process = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    state.scanning = True
    asyncio.create_task(scan_loop())
    alert_engine.add_alert("INFO", "Escaneo Wi-Fi iniciado")
    return {"status": "started"}


@app.post("/api/scan/stop")
async def stop_scan(username: str = Depends(verify_credentials)):
    if state.scan_process:
        state.scan_process.terminate()
        state.scan_process = None
    state.scanning = False
    alert_engine.add_alert("INFO", "Escaneo Wi-Fi detenido")
    return {"status": "stopped"}


# --- Ataques ---
async def attack_ws_callback(attack_id: str, line: str, finished: bool = False):
    msg = {"type": "attack_output" if not finished else "attack_finished", "id": attack_id}
    if not finished:
        msg["line"] = line
        msg["timestamp"] = datetime.now().isoformat()
    await manager.broadcast(msg)


@app.post("/api/attack/deauth")
async def attack_deauth(bssid: str, client_mac: str = None, count: int = 10, username: str = Depends(verify_credentials)):
    ensure_active()
    if not state.monitor_interface:
        return {"error": "Modo monitor no activo"}
    attack_id = await attack_manager.launch_deauth(state.monitor_interface, bssid, client_mac, count, attack_ws_callback)
    alert_engine.add_alert("WARNING", f"Lanzando Deauth contra {bssid} (Client: {client_mac})", "attacker")
    return {"attack_id": attack_id}


@app.post("/api/attack/pmkid")
async def attack_pmkid(channel: int, username: str = Depends(verify_credentials)):
    ensure_active()
    if not state.monitor_interface:
        return {"error": "Modo monitor no activo"}
    attack_id, pcap_path = await attack_manager.launch_pmkid_attack(state.monitor_interface, channel, attack_ws_callback)
    alert_engine.add_alert("WARNING", f"Ataque PMKID iniciado en CH {channel}", "attacker")
    return {"attack_id": attack_id, "pcap_path": pcap_path}


@app.post("/api/attack/stop/{attack_id}")
async def stop_attack(attack_id: str, username: str = Depends(verify_credentials)):
    success = attack_manager.stop_attack(attack_id)
    return {"status": "stopped" if success else "not_found"}


# --- nmap ---
@app.post("/api/ports/scan")
async def scan_ports(target_ip: str, profile: str = "rápido", username: str = Depends(verify_credentials)):
    alert_engine.add_alert("INFO", f"Iniciando escaneo nmap a {target_ip} ({profile})", "nmap")
    asyncio.create_task(run_nmap_and_notify(target_ip, profile))
    return {"status": "started", "target": target_ip}


async def run_nmap_and_notify(target_ip: str, profile: str):
    results = await nmap_scanner.scan(target_ip, profile)
    await manager.broadcast({"type": "nmap_finished", "target": target_ip, "results": results})
    alert_engine.add_alert("INFO", f"Escaneo nmap a {target_ip} finalizado", "nmap")


# --- Inventario de red + persistencia (base de los informes) ---
@app.post("/api/inventory/scan")
async def inventory_scan(target: str, objetivo: str, with_os: bool = False, username: str = Depends(verify_credentials)):
    """Escanea una red/host, guarda el inventario bajo `objetivo` y devuelve el id del escaneo."""
    alert_engine.add_alert("INFO", f"Inventario de red sobre {target} (objetivo: {objetivo})", "nmap")
    hosts = await nmap_scanner.scan_inventory(target, with_os=with_os)
    if hosts and isinstance(hosts[0], dict) and hosts[0].get("error"):
        return {"error": hosts[0]["error"]}
    escaneo_id = db_manager.guardar_hosts(objetivo, hosts, tipo="Inventario nmap")
    return {"status": "ok", "escaneo_id": escaneo_id, "dispositivos": len(hosts)}


@app.get("/api/scans")
async def list_scans(username: str = Depends(verify_credentials)):
    return {"scans": db_manager.listar_escaneos()}


@app.get("/api/diff")
async def diff_scans(base_id: int, target_id: int, username: str = Depends(verify_credentials)):
    """Compara dos escaneos: qué dispositivos/puertos han cambiado entre ambos."""
    resultado = db_manager.comparar_escaneos(base_id, target_id)
    if resultado is None:
        raise HTTPException(status_code=404, detail="Uno de los escaneos no existe")
    return resultado


# --- Crackeo de handshakes ---
async def crack_ws_callback(job_id: str, line: str, finished: bool = False, key: str = None):
    msg = {"type": "crack_finished" if finished else "crack_output", "id": job_id, "line": line}
    if finished:
        msg["key"] = key
    await manager.broadcast(msg)


@app.get("/api/captures")
async def list_captures(username: str = Depends(verify_credentials)):
    return {"captures": crack_manager.list_captures(), "wordlist_ok": crack_manager.wordlist_ok()}


@app.post("/api/crack/aircrack")
async def crack_aircrack(capture: str, bssid: str = None, wordlist: str = None, username: str = Depends(verify_credentials)):
    ensure_active()
    res = await crack_manager.crack_aircrack(capture, bssid, wordlist, crack_ws_callback)
    if "error" not in res:
        alert_engine.add_alert("WARNING", f"Crackeo (aircrack) iniciado sobre {os.path.basename(capture)}", "cracker")
    return res


@app.post("/api/crack/hashcat")
async def crack_hashcat(capture: str, wordlist: str = None, username: str = Depends(verify_credentials)):
    ensure_active()
    res = await crack_manager.crack_hashcat(capture, wordlist, crack_ws_callback)
    if "error" not in res:
        alert_engine.add_alert("WARNING", f"Crackeo (hashcat) iniciado sobre {os.path.basename(capture)}", "cracker")
    return res


@app.post("/api/crack/stop/{job_id}")
async def crack_stop(job_id: str, username: str = Depends(verify_credentials)):
    return {"status": "stopped" if crack_manager.stop(job_id) else "not_found"}


# --- Modo naval: NMEA ---
@app.post("/api/naval/nmea")
async def naval_nmea(ip: str, puerto: int = 10110, lineas: int = 5, username: str = Depends(verify_credentials)):
    resultado = await nmea.capturar_nmea_async(ip, puerto, lineas)
    nivel = "CRITICAL" if resultado.get("exito") else "INFO"
    alert_engine.add_alert(nivel, f"PoC NMEA en {ip}:{puerto} — {'datos en claro capturados' if resultado.get('exito') else 'sin datos'}", "naval")
    return resultado


@app.post("/api/naval/nmea/auto")
async def naval_nmea_auto(ip: str, username: str = Depends(verify_credentials)):
    """Prueba los puertos NMEA habituales sobre una IP."""
    salidas = []
    for puerto in NMEA_PORTS:
        salidas.append(await nmea.capturar_nmea_async(ip, puerto, 5))
    return {"ip": ip, "resultados": salidas}


# --- Informes ---
@app.get("/api/report/{escaneo_id}")
async def get_report(escaneo_id: int, username: str = Depends(verify_credentials)):
    scan = db_manager.obtener_escaneo(escaneo_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Escaneo no encontrado")
    resultado = report.generar_informe(scan)
    if resultado["formato"] == "pdf":
        return FileResponse(resultado["ruta"], media_type="application/pdf",
                            filename=os.path.basename(resultado["ruta"]))
    return HTMLResponse(content=resultado["contenido"])


# --- WebSocket ---
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)
