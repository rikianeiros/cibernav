import logging
import subprocess
import re

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class WifiMonitor:
    """
    Módulo para controlar la tarjeta de red (ej: Alfa AWUS036ACH) en modo monitor.
    Nota: Requiere ejecución con 'sudo' en Kali Linux.
    """

    def __init__(self, interface="wlan0"):
        self.interface = interface
        self.monitor_interface = None

    def activar_modo_monitor(self):
        """
        Pone la tarjeta en modo monitor usando airmon-ng.
        Lee el nombre real de la interfaz de monitor del output del comando,
        en lugar de asumir que es siempre 'wlan0mon'.
        """
        logger.info(f"Activando modo monitor en {self.interface}...")
        try:
            subprocess.run(['airmon-ng', 'check', 'kill'], check=True, capture_output=True)
            result = subprocess.run(
                ['airmon-ng', 'start', self.interface],
                check=True, capture_output=True, text=True
            )
            # Leer el nombre real de la interfaz monitor del output de airmon-ng
            # El output suele contener algo como "monitor mode vif enabled for... on wlan0mon"
            match = re.search(r'on\s+(\w+mon\w*)', result.stdout)
            if match:
                self.monitor_interface = match.group(1)
            else:
                # Fallback: asumir nombre estándar
                self.monitor_interface = self.interface + "mon"

            logger.info(f"Modo monitor activado en: {self.monitor_interface}")
            return True
        except FileNotFoundError:
            logger.error("airmon-ng no encontrado. Instala el paquete aircrack-ng: sudo apt install aircrack-ng")
            return False
        except subprocess.CalledProcessError as e:
            logger.error(f"Fallo al activar modo monitor: {e}")
            return False

    def desactivar_modo_monitor(self):
        """Devuelve la tarjeta a modo normal (managed)."""
        iface = self.monitor_interface or (self.interface + "mon")
        try:
            subprocess.run(['airmon-ng', 'stop', iface], check=True, capture_output=True)
            logger.info(f"Modo monitor desactivado en {iface}.")
            return True
        except Exception as e:
            logger.error(f"Fallo al desactivar modo monitor: {e}")
            return False

    def sniff_probe_requests(self, timeout=60):
        """
        Escucha pasivamente para capturar Probe Requests de los móviles.
        
        ESTADO: PENDIENTE DE IMPLEMENTACIÓN.
        Esta función requiere que Scapy esté disponible y que la interfaz
        esté en modo monitor. La implementación real usará:
            from scapy.all import sniff, Dot11ProbeReq
        """
        if not self.monitor_interface:
            logger.error("Activa primero el modo monitor con activar_modo_monitor().")
            return []

        logger.warning("sniff_probe_requests() aún no está implementado con Scapy real.")
        return []

    def capturar_handshake(self, bssid, canal, output_file="captura_handshake", timeout=120):
        """
        Captura el 4-way handshake WPA/WPA2 de una red usando airodump-ng.
        El archivo .pcap resultante puede analizarse con aircrack-ng o hashcat.
        
        Retorna la ruta al fichero .cap generado, o None si falla.
        """
        if not self.monitor_interface:
            logger.error("Activa primero el modo monitor.")
            return None

        cmd = [
            'airodump-ng',
            '-c', str(canal),
            '--bssid', bssid,
            '-w', output_file,
            '--output-format', 'pcap',
            self.monitor_interface
        ]
        logger.info(f"Iniciando captura de handshake para {bssid} en canal {canal}...")
        logger.info(f"Comando: {' '.join(cmd)}")
        logger.info(f"Escuchando durante {timeout} segundos...")

        try:
            subprocess.run(cmd, timeout=timeout, capture_output=True)
            ruta_pcap = f"{output_file}-01.cap"
            logger.info(f"Captura finalizada. Archivo guardado en: {ruta_pcap}")
            return ruta_pcap
        except subprocess.TimeoutExpired:
            logger.info("Tiempo de captura agotado. Analizando archivo resultante...")
            return f"{output_file}-01.cap"
        except Exception as e:
            logger.error(f"Error en captura de handshake: {e}")
            return None


if __name__ == '__main__':
    print("[*] Módulo WiFi Monitor cargado.")
    print("[*] Uso: wm = WifiMonitor('wlan0') -> wm.activar_modo_monitor() -> wm.capturar_handshake(...)")
