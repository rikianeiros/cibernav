"""
Persistencia en SQLite.

Guarda el histórico de escaneos agrupados por "objetivo" (un buque, una casa,
una oficina...), con su inventario de dispositivos, servicios y puertos. Sirve
de base para los informes.
"""
import sqlite3
import os

from config import DB_PATH


def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    with get_connection() as conn:
        c = conn.cursor()
        c.execute("""
            CREATE TABLE IF NOT EXISTS objetivos (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                nombre TEXT NOT NULL UNIQUE,
                tipo TEXT DEFAULT 'red',
                fecha_registro TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS escaneos (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                objetivo_id INTEGER,
                fecha TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                tipo_escaneo TEXT,
                FOREIGN KEY(objetivo_id) REFERENCES objetivos(id)
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS dispositivos (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                mac TEXT NOT NULL UNIQUE,
                fabricante TEXT,
                tipo_dispositivo TEXT
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS avistamientos (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                escaneo_id INTEGER,
                dispositivo_id INTEGER,
                ip TEXT,
                hostname TEXT,
                os_detectado TEXT,
                FOREIGN KEY(escaneo_id) REFERENCES escaneos(id),
                FOREIGN KEY(dispositivo_id) REFERENCES dispositivos(id)
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS servicios (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                avistamiento_id INTEGER,
                puerto INTEGER,
                protocolo TEXT,
                servicio TEXT,
                version TEXT,
                FOREIGN KEY(avistamiento_id) REFERENCES avistamientos(id)
            )
        """)


class DBManager:
    """Operaciones de alto nivel sobre la base de datos."""

    def registrar_objetivo(self, nombre: str, tipo: str = "red") -> int:
        with get_connection() as conn:
            c = conn.cursor()
            c.execute("INSERT OR IGNORE INTO objetivos (nombre, tipo) VALUES (?, ?)", (nombre, tipo))
            c.execute("SELECT id FROM objetivos WHERE nombre = ?", (nombre,))
            return c.fetchone()["id"]

    def crear_escaneo(self, objetivo_id: int, tipo: str = "Nmap") -> int:
        with get_connection() as conn:
            c = conn.cursor()
            c.execute("INSERT INTO escaneos (objetivo_id, tipo_escaneo) VALUES (?, ?)", (objetivo_id, tipo))
            return c.lastrowid

    def guardar_hosts(self, objetivo_nombre: str, hosts: list[dict], tipo: str = "Nmap") -> int | None:
        """
        Guarda una lista de hosts (formato del scanner nmap) bajo un objetivo.
        Cada host: {ip, hostname, mac, vendor, os, puertos:[{puerto,protocolo,servicio,version}]}
        Devuelve el id del escaneo, o None si no hay hosts.
        """
        if not hosts:
            return None
        objetivo_id = self.registrar_objetivo(objetivo_nombre)
        escaneo_id = self.crear_escaneo(objetivo_id, tipo)
        with get_connection() as conn:
            c = conn.cursor()
            for host in hosts:
                mac = host.get("mac", "Desconocida")
                mac_key = mac if mac != "Desconocida" else f"NO_MAC_{host.get('ip', 'unknown')}"
                c.execute(
                    "INSERT OR IGNORE INTO dispositivos (mac, fabricante) VALUES (?, ?)",
                    (mac_key, host.get("vendor", "Desconocido")),
                )
                c.execute("SELECT id FROM dispositivos WHERE mac = ?", (mac_key,))
                dispositivo_id = c.fetchone()["id"]
                c.execute(
                    """INSERT INTO avistamientos (escaneo_id, dispositivo_id, ip, hostname, os_detectado)
                       VALUES (?, ?, ?, ?, ?)""",
                    (escaneo_id, dispositivo_id, host.get("ip"), host.get("hostname", ""), host.get("os", "Desconocido")),
                )
                avistamiento_id = c.lastrowid
                for p in host.get("puertos", []):
                    c.execute(
                        """INSERT INTO servicios (avistamiento_id, puerto, protocolo, servicio, version)
                           VALUES (?, ?, ?, ?, ?)""",
                        (avistamiento_id, p.get("puerto"), p.get("protocolo"), p.get("servicio"), p.get("version")),
                    )
        return escaneo_id

    def obtener_escaneo(self, escaneo_id: int) -> dict | None:
        """Reconstruye un escaneo completo para el informe."""
        with get_connection() as conn:
            c = conn.cursor()
            esc = c.execute(
                """SELECT e.id, e.fecha, e.tipo_escaneo, o.nombre AS objetivo
                   FROM escaneos e JOIN objetivos o ON o.id = e.objetivo_id
                   WHERE e.id = ?""", (escaneo_id,),
            ).fetchone()
            if not esc:
                return None
            avistamientos = c.execute(
                """SELECT a.id, a.ip, a.hostname, a.os_detectado, d.mac, d.fabricante
                   FROM avistamientos a JOIN dispositivos d ON d.id = a.dispositivo_id
                   WHERE a.escaneo_id = ?""", (escaneo_id,),
            ).fetchall()
            hosts = []
            for a in avistamientos:
                servicios = c.execute(
                    "SELECT puerto, protocolo, servicio, version FROM servicios WHERE avistamiento_id = ?",
                    (a["id"],),
                ).fetchall()
                hosts.append({
                    "ip": a["ip"], "hostname": a["hostname"], "os": a["os_detectado"],
                    "mac": a["mac"], "fabricante": a["fabricante"],
                    "servicios": [dict(s) for s in servicios],
                })
            return {
                "id": esc["id"], "fecha": esc["fecha"], "tipo": esc["tipo_escaneo"],
                "objetivo": esc["objetivo"], "hosts": hosts,
            }

    @staticmethod
    def _clave_host(h: dict) -> str:
        """Identificador estable de un host: MAC si es real, si no la IP."""
        mac = h.get("mac", "")
        if mac and mac != "Desconocida" and not mac.startswith("NO_MAC"):
            return mac
        return h.get("ip", "?")

    def comparar_escaneos(self, base_id: int, target_id: int) -> dict | None:
        """
        Compara dos escaneos (idealmente del mismo objetivo) y devuelve qué ha
        cambiado: dispositivos nuevos, desaparecidos, y puertos abiertos/cerrados
        en los que siguen presentes.
        """
        base = self.obtener_escaneo(base_id)
        target = self.obtener_escaneo(target_id)
        if not base or not target:
            return None

        def indexar(scan):
            idx = {}
            for h in scan["hosts"]:
                idx[self._clave_host(h)] = {
                    "host": h,
                    "puertos": {(s["protocolo"], s["puerto"]) for s in h["servicios"]},
                }
            return idx

        b, t = indexar(base), indexar(target)
        nuevos = [t[k]["host"] for k in t if k not in b]
        desaparecidos = [b[k]["host"] for k in b if k not in t]
        cambios = []
        for k in t:
            if k not in b:
                continue
            abiertos = sorted(t[k]["puertos"] - b[k]["puertos"], key=lambda x: x[1])
            cerrados = sorted(b[k]["puertos"] - t[k]["puertos"], key=lambda x: x[1])
            if abiertos or cerrados:
                cambios.append({
                    "dispositivo": t[k]["host"],
                    "puertos_abiertos": [{"protocolo": p, "puerto": n} for p, n in abiertos],
                    "puertos_cerrados": [{"protocolo": p, "puerto": n} for p, n in cerrados],
                })
        return {
            "base": {"id": base["id"], "fecha": base["fecha"], "objetivo": base["objetivo"]},
            "target": {"id": target["id"], "fecha": target["fecha"], "objetivo": target["objetivo"]},
            "dispositivos_nuevos": nuevos,
            "dispositivos_desaparecidos": desaparecidos,
            "cambios_puertos": cambios,
            "sin_cambios": not (nuevos or desaparecidos or cambios),
        }

    def listar_escaneos(self) -> list[dict]:
        with get_connection() as conn:
            rows = conn.execute(
                """SELECT e.id, e.fecha, e.tipo_escaneo, o.nombre AS objetivo
                   FROM escaneos e JOIN objetivos o ON o.id = e.objetivo_id
                   ORDER BY e.fecha DESC""",
            ).fetchall()
            return [dict(r) for r in rows]


db_manager = DBManager()
