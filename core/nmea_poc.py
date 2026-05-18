import socket
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def capturar_nmea(ip, puerto=10110, num_lineas=5, timeout=5):
    """
    Prueba de Concepto (PoC): Intenta conectarse a un puerto NMEA TCP y capturar sentencias.
    Si tiene éxito, demuestra que los datos de navegación viajan en claro sin autenticación.
    """
    capturas = []
    logger.info(f"Intentando capturar tráfico NMEA en {ip}:{puerto}...")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, puerto))
        
        # Leemos datos
        buffer = ""
        while len(capturas) < num_lineas:
            data = s.recv(1024).decode('ascii', errors='ignore')
            if not data:
                break
            buffer += data
            
            # Extraer sentencias completas (típicamente empiezan por $ o ! y terminan con CRLF)
            while '\n' in buffer:
                linea, buffer = buffer.split('\n', 1)
                linea = linea.strip()
                if linea.startswith('$') or linea.startswith('!'):
                    capturas.append(linea)
                    if len(capturas) >= num_lineas:
                        break
        s.close()
        return capturas
    except Exception as e:
        logger.warning(f"No se pudo capturar NMEA en {ip}:{puerto} - {e}")
        return None

if __name__ == '__main__':
    print("[*] Módulo NMEA PoC cargado. Listo para pruebas en alta mar.")
