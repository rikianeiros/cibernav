import sqlite3
from core.database import get_connection

class DBManager:
    def __init__(self):
        pass

    def registrar_buque(self, nombre):
        """Registra un buque si no existe y devuelve su ID."""
        with get_connection() as conn:
            c = conn.cursor()
            c.execute("INSERT OR IGNORE INTO buques (nombre) VALUES (?)", (nombre,))
            c.execute("SELECT id FROM buques WHERE nombre = ?", (nombre,))
            return c.fetchone()['id']

    def crear_escaneo(self, buque_id, tipo="Nmap Local"):
        """Crea un nuevo escaneo para un buque y devuelve el ID del escaneo."""
        with get_connection() as conn:
            c = conn.cursor()
            c.execute("INSERT INTO escaneos (buque_id, tipo_escaneo) VALUES (?, ?)", (buque_id, tipo))
            return c.lastrowid

    def procesar_resultados_nmap(self, buque_nombre, resultados):
        """
        Toma la lista de diccionarios de scanner_nmap.py y la inserta en la BD.
        Gestiona la conexión con context manager para evitar connection leaks.
        Dispositivos con MAC 'Desconocida' se guardan con la IP como identificador 
        para evitar colisiones entre hosts sin MAC visible.
        """
        if not resultados:
            return None

        buque_id = self.registrar_buque(buque_nombre)
        escaneo_id = self.crear_escaneo(buque_id, tipo="Nmap Completo")

        with get_connection() as conn:
            c = conn.cursor()

            for host in resultados:
                mac = host.get("mac", "Desconocida")

                # FIX: Si la MAC es desconocida (host fuera de subred LAN),
                # usamos un identificador único basado en la IP para no colisionar.
                if mac == "Desconocida":
                    mac_key = f"NO_MAC_{host.get('ip', 'unknown')}"
                else:
                    mac_key = mac

                # Registrar o localizar el dispositivo
                c.execute(
                    "INSERT OR IGNORE INTO dispositivos (mac, fabricante) VALUES (?, ?)",
                    (mac_key, host.get("vendor", "Desconocido"))
                )
                c.execute("SELECT id FROM dispositivos WHERE mac = ?", (mac_key,))
                dispositivo_id = c.fetchone()['id']

                # Registrar el avistamiento
                c.execute("""
                    INSERT INTO avistamientos (escaneo_id, dispositivo_id, ip, hostname, os_detectado)
                    VALUES (?, ?, ?, ?, ?)
                """, (
                    escaneo_id, dispositivo_id,
                    host.get("ip"), host.get("hostname", ""),
                    host.get("os", "Desconocido")
                ))
                avistamiento_id = c.lastrowid

                # Registrar puertos y servicios
                for puerto in host.get("puertos", []):
                    c.execute("""
                        INSERT INTO servicios (avistamiento_id, puerto, protocolo, servicio, version)
                        VALUES (?, ?, ?, ?, ?)
                    """, (
                        avistamiento_id,
                        puerto.get("puerto"), puerto.get("protocolo"),
                        puerto.get("servicio"), puerto.get("version")
                    ))

        return escaneo_id
