"""
Módulo NMEA (modo naval).

Prueba de concepto: se conecta a un puerto NMEA por TCP y captura sentencias
de navegación. Si tiene éxito, demuestra que los datos de navegación (posición
GPS, rumbo, velocidad) viajan en claro, sin cifrado ni autenticación.
"""
import asyncio
import socket
import logging

logger = logging.getLogger(__name__)

# Descripción breve de las sentencias NMEA más habituales, para el informe.
NMEA_SENTENCES = {
    "GGA": "Posición GPS fija (latitud, longitud, altitud)",
    "RMC": "Datos mínimos recomendados: posición, velocidad y rumbo",
    "GLL": "Latitud y longitud geográfica",
    "VTG": "Rumbo y velocidad sobre el fondo",
    "GSV": "Satélites GPS a la vista",
    "HDT": "Rumbo verdadero",
    "VHW": "Velocidad y rumbo respecto al agua",
    "DPT": "Profundidad bajo la sonda",
    "MWV": "Viento (ángulo y velocidad)",
}


def _sentence_type(linea: str) -> str:
    """Extrae el tipo de sentencia (p. ej. '$GPGGA' -> 'GGA')."""
    core = linea[1:] if linea[:1] in "$!" else linea
    talker = core.split(",", 1)[0]
    return talker[-3:] if len(talker) >= 3 else talker


def capturar_nmea(ip: str, puerto: int = 10110, num_lineas: int = 5, timeout: int = 5):
    """Captura bloqueante de sentencias NMEA por TCP. Devuelve lista o None."""
    capturas = []
    logger.info(f"Intentando capturar tráfico NMEA en {ip}:{puerto}...")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, puerto))
        buffer = ""
        while len(capturas) < num_lineas:
            data = s.recv(1024).decode("ascii", errors="ignore")
            if not data:
                break
            buffer += data
            while "\n" in buffer:
                linea, buffer = buffer.split("\n", 1)
                linea = linea.strip()
                if linea.startswith("$") or linea.startswith("!"):
                    capturas.append(linea)
                    if len(capturas) >= num_lineas:
                        break
        s.close()
        return capturas
    except Exception as e:
        logger.warning(f"No se pudo capturar NMEA en {ip}:{puerto} - {e}")
        return None


async def capturar_nmea_async(ip: str, puerto: int = 10110, num_lineas: int = 5, timeout: int = 5) -> dict:
    """
    Versión asíncrona para FastAPI. Devuelve un dict con el resultado y una
    interpretación lista para mostrar.
    """
    loop = asyncio.get_event_loop()
    capturas = await loop.run_in_executor(
        None, lambda: capturar_nmea(ip, puerto, num_lineas, timeout)
    )
    if capturas is None:
        return {
            "ip": ip,
            "puerto": puerto,
            "exito": False,
            "mensaje": "No se recibieron datos NMEA (puerto cerrado, filtrado o sin emisión).",
            "sentencias": [],
        }

    sentencias = []
    for linea in capturas:
        tipo = _sentence_type(linea)
        sentencias.append({
            "raw": linea,
            "tipo": tipo,
            "descripcion": NMEA_SENTENCES.get(tipo, "Sentencia NMEA no catalogada"),
        })

    return {
        "ip": ip,
        "puerto": puerto,
        "exito": bool(sentencias),
        "riesgo": "CRÍTICO" if sentencias else "N/A",
        "mensaje": (
            "Datos de navegación capturados en claro. La red náutica NO está aislada "
            "ni cifrada: cualquiera con acceso a la red puede leer (y potencialmente "
            "falsear) la posición y el rumbo del buque."
            if sentencias else "Sin datos."
        ),
        "recomendacion": (
            "Aislar la red náutica (NMEA/instrumentación) de la red de tripulación e "
            "invitados mediante VLAN o segmentación física. Este servicio no debe ser "
            "accesible desde la red general."
        ),
        "sentencias": sentencias,
    }
