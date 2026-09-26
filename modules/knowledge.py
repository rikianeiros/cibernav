"""
Base de conocimiento: traduce hallazgos técnicos (puertos, cifrados, MACs) a
explicaciones claras con su nivel de riesgo, implicaciones y recomendaciones.

Fusiona el conocimiento general de red/IoT con los puertos específicos de
entornos náuticos (NMEA), para que el mismo escáner sirva en una casa, una
oficina o un buque.
"""

PORT_KNOWLEDGE = {
    21: {
        "servicio": "FTP — File Transfer Protocol",
        "riesgo": "ALTO",
        "descripcion": "Protocolo de transferencia de archivos sin cifrado. Las credenciales y los archivos viajan en texto plano por la red.",
        "implicaciones": [
            "Credenciales (usuario/contraseña) visibles en la red",
            "Archivos transferidos accesibles por cualquier escucha",
            "Frecuentemente usado por dispositivos IoT para actualizaciones",
        ],
        "recomendacion": "Sustituir por SFTP (puerto 22) o FTPS. Si no es necesario, cerrar el puerto.",
    },
    22: {
        "servicio": "SSH — Secure Shell",
        "riesgo": "MEDIO",
        "descripcion": "Administración remota cifrada. Normal en routers y servidores. El riesgo viene de configuraciones débiles.",
        "implicaciones": [
            "Acceso completo al dispositivo si las credenciales son débiles",
            "Ataques de fuerza bruta si no hay limitación de intentos",
        ],
        "recomendacion": "Verificar versión de OpenSSH. Deshabilitar acceso root. Usar claves en lugar de contraseñas.",
    },
    23: {
        "servicio": "Telnet",
        "riesgo": "CRÍTICO",
        "descripcion": "Administración remota SIN cifrado, obsoleta. Todo lo que se escriba (incluidas contraseñas) es visible en la red.",
        "implicaciones": [
            "Credenciales de administración en texto plano",
            "Muchos dispositivos IoT tienen Telnet activo con credenciales por defecto",
        ],
        "recomendacion": "Cerrar inmediatamente. Aislar el dispositivo si no se puede desactivar.",
    },
    69: {
        "servicio": "TFTP — Trivial FTP",
        "riesgo": "ALTO",
        "descripcion": "Versión ultraligera de FTP sin ningún tipo de autenticación. Cualquiera en la red puede descargar y subir archivos.",
        "implicaciones": ["Acceso de lectura/escritura sin autenticación", "Usado para volcar/cargar firmware de equipos"],
        "recomendacion": "Deshabilitar si no es estrictamente necesario.",
    },
    80: {
        "servicio": "HTTP — Web sin cifrado",
        "riesgo": "MEDIO-ALTO",
        "descripcion": "Interfaz web sin cifrado. En routers e IoT suele ser el panel de administración. El tráfico es interceptable.",
        "implicaciones": [
            "Panel de administración accesible sin HTTPS",
            "Credenciales de login visibles si hay un atacante en la red",
            "Posible inyección de contenido mediante MITM",
        ],
        "recomendacion": "Acceder siempre por HTTPS (puerto 443). Cambiar contraseña si no hay HTTPS.",
    },
    139: {
        "servicio": "NetBIOS — Identificación Windows",
        "riesgo": "BAJO",
        "descripcion": "Protocolo antiguo de Windows que anuncia el nombre del equipo y del grupo de trabajo en la red.",
        "implicaciones": ["Revela información del equipo y del dominio"],
        "recomendacion": "Deshabilitar si no es necesario.",
    },
    161: {
        "servicio": "SNMP — Gestión de red",
        "riesgo": "ALTO",
        "descripcion": "Gestión de red. Con la cadena de comunidad por defecto ('public') expone toda la configuración del router o switch.",
        "implicaciones": ["Configuración de red completa expuesta", "Posible reconfiguración si es escritura"],
        "recomendacion": "Cambiar la community string o deshabilitar si no se gestiona activamente.",
    },
    443: {
        "servicio": "HTTPS — Web cifrada",
        "riesgo": "BAJO",
        "descripcion": "Interfaz web cifrada con TLS. El tráfico está protegido.",
        "implicaciones": ["Certificados autofirmados pueden ser suplantados (MITM con aviso ignorado)"],
        "recomendacion": "Verificar validez del certificado y que la contraseña no es la de fábrica.",
    },
    445: {
        "servicio": "SMB — Compartición de archivos Windows",
        "riesgo": "MEDIO-ALTO",
        "descripcion": "Servicio de Windows para compartir carpetas. Mal configurado puede exponer documentos internos y es objetivo frecuente de ransomware.",
        "implicaciones": ["Carpetas compartidas accesibles", "Histórico de vulnerabilidades críticas (EternalBlue)"],
        "recomendacion": "Requerir autenticación, mantener el sistema actualizado y no exponer SMB a redes no confiables.",
    },
    554: {
        "servicio": "RTSP — Real Time Streaming Protocol",
        "riesgo": "ALTO",
        "descripcion": "Streaming de vídeo en tiempo real. Indica una cámara IP o sistema de vigilancia.",
        "implicaciones": ["Acceso al feed de vídeo de la cámara", "Muchas cámaras IP usan admin/admin"],
        "recomendacion": "Cambiar credenciales por defecto. Aislar cámaras en una VLAN separada.",
    },
    1900: {
        "servicio": "UPnP — Universal Plug and Play",
        "riesgo": "ALTO",
        "descripcion": "Autodescubrimiento de dispositivos. Riesgo de apertura de puertos no deseados hacia el exterior.",
        "implicaciones": ["Modificación de reglas de reenvío de puertos"],
        "recomendacion": "Deshabilitar UPnP en el router.",
    },
    2000: {
        "servicio": "NMEA 2000 / bus náutico expuesto",
        "riesgo": "ALTO",
        "descripcion": "Puede ser el bus de datos NMEA 2000 accesible por red, lo que permite leer y potencialmente inyectar datos de navegación.",
        "implicaciones": ["Lectura de datos de instrumentación del buque", "Posible inyección de datos falsos de navegación"],
        "recomendacion": "Verificar qué servicio corre realmente y aislar la red náutica.",
    },
    3306: {
        "servicio": "MySQL — Base de datos",
        "riesgo": "ALTO",
        "descripcion": "Base de datos MySQL expuesta en red. Si acepta conexiones desde cualquier IP, es un objetivo directo.",
        "implicaciones": ["Acceso potencial a todos los datos almacenados"],
        "recomendacion": "Limitar el acceso a 127.0.0.1. Nunca debe estar accesible desde la red general.",
    },
    3389: {
        "servicio": "RDP — Escritorio remoto",
        "riesgo": "ALTO",
        "descripcion": "Control remoto de un PC Windows. Con contraseña débil, un atacante puede tomar el control total del equipo.",
        "implicaciones": ["Control total del equipo", "Objetivo frecuente de fuerza bruta y ransomware"],
        "recomendacion": "No exponer a Internet. Usar VPN, contraseñas robustas y limitar por IP.",
    },
    5432: {
        "servicio": "PostgreSQL — Base de datos",
        "riesgo": "ALTO",
        "descripcion": "Base de datos PostgreSQL expuesta en red. Mismo riesgo que MySQL.",
        "implicaciones": ["Acceso potencial a todos los datos almacenados"],
        "recomendacion": "Limitar el acceso a solo conexiones locales.",
    },
    5900: {
        "servicio": "VNC — Control remoto de escritorio",
        "riesgo": "ALTO",
        "descripcion": "Control remoto de escritorio, a menudo configurado sin contraseña o con la de fábrica.",
        "implicaciones": ["Control del escritorio remoto", "Frecuentemente sin autenticación"],
        "recomendacion": "Deshabilitar si no se usa. Configurar contraseña fuerte y túnel cifrado.",
    },
    8080: {
        "servicio": "HTTP alternativo / Panel de administración",
        "riesgo": "MEDIO-ALTO",
        "descripcion": "Puerto HTTP alternativo, habitual en paneles de routers, cámaras o dispositivos IoT.",
        "implicaciones": ["Credenciales por defecto muy frecuentes en este tipo de dispositivos"],
        "recomendacion": "Cambiar credenciales por defecto. Migrar a HTTPS si es posible.",
    },
    8443: {
        "servicio": "HTTPS alternativo",
        "riesgo": "BAJO",
        "descripcion": "Panel web cifrado en puerto alternativo.",
        "implicaciones": ["Certificados autofirmados suplantables"],
        "recomendacion": "Verificar el certificado y cambiar las credenciales por defecto.",
    },
    10110: {
        "servicio": "NMEA 0183 sobre TCP (datos náuticos)",
        "riesgo": "CRÍTICO",
        "descripcion": "Puerto marítimo estándar que emite datos de navegación en tiempo real (posición GPS, rumbo, velocidad) sin ninguna autenticación ni cifrado.",
        "implicaciones": [
            "Posición y rumbo del buque legibles por cualquiera en la red",
            "Posible falseo de datos de navegación (spoofing)",
            "Red náutica no aislada de la red de tripulación/invitados",
        ],
        "recomendacion": "Aislar la red náutica mediante VLAN o segmentación física. Este servicio no debe ser accesible desde la red general.",
    },
    27017: {
        "servicio": "MongoDB — Base de datos",
        "riesgo": "ALTO",
        "descripcion": "Base de datos MongoDB expuesta en red. Históricamente configurada sin contraseña, exponiendo todos los datos.",
        "implicaciones": ["Acceso potencial a toda la base de datos sin autenticación"],
        "recomendacion": "Habilitar autenticación y limitar el acceso a la IP local.",
    },
}


def get_port_knowledge(port: int, service: str = "") -> dict:
    """Devuelve la ficha de un puerto, o un genérico si no está catalogado."""
    return PORT_KNOWLEDGE.get(port, {
        "servicio": service or f"Servicio no catalogado (puerto {port})",
        "riesgo": "DESCONOCIDO",
        "descripcion": "Puerto abierto sin información específica en la base de conocimiento.",
        "implicaciones": ["Investigar manualmente"],
        "recomendacion": "Verificar qué aplicación usa este puerto y si es necesario que esté abierto.",
    })


CIPHER_KNOWLEDGE = {
    "OPN": {
        "nombre": "Red abierta (sin cifrado)",
        "riesgo": "CRÍTICO",
        "descripcion": "La red no usa ningún cifrado. Todo el tráfico Wi-Fi es visible. Cualquiera puede conectarse.",
        "implicaciones": ["Todo el tráfico HTTP es interceptable", "No requiere autenticación"],
        "ataques_posibles": ["Sniffing pasivo", "MITM", "Inyección de tráfico"],
    },
    "WEP": {
        "nombre": "WEP — Wired Equivalent Privacy",
        "riesgo": "CRÍTICO",
        "descripcion": "Cifrado roto desde 2007. Puede crackearse en minutos.",
        "implicaciones": ["Clave de red recuperable muy rápido"],
        "ataques_posibles": ["Aircrack-ng (estadístico)", "ChopChop"],
    },
    "WPA": {
        "nombre": "WPA — Wi-Fi Protected Access (v1)",
        "riesgo": "ALTO",
        "descripcion": "Usa TKIP, con vulnerabilidades. Prácticamente obsoleto.",
        "implicaciones": ["Vulnerable a ataques sobre TKIP", "Handshake atacable"],
        "ataques_posibles": ["Handshake capture + diccionario"],
    },
    "WPA-MIGR": {
        "nombre": "WPA/WPA2 modo migración",
        "riesgo": "ALTO",
        "descripcion": "Acepta WPA y WPA2. La seguridad efectiva es la del protocolo más débil (WPA).",
        "implicaciones": ["El tráfico WPA puede ser interceptado"],
        "ataques_posibles": ["Forzar downgrade a WPA"],
    },
    "WPA2": {
        "nombre": "WPA2 — Wi-Fi Protected Access 2",
        "riesgo": "MEDIO",
        "descripcion": "Estándar más extendido. Usa AES-CCMP. Riesgo principal: contraseña débil o PMKID expuesto.",
        "implicaciones": ["Seguro si la contraseña es fuerte", "Vulnerable si el router expone PMKID"],
        "ataques_posibles": ["Handshake + diccionario", "PMKID attack (hcxdumptool)", "WPS si está activo"],
    },
    "WPA3": {
        "nombre": "WPA3 — Wi-Fi Protected Access 3",
        "riesgo": "BAJO",
        "descripcion": "Usa SAE, que previene ataques de diccionario offline.",
        "implicaciones": ["No vulnerable a ataques de diccionario offline tradicionales"],
        "ataques_posibles": ["Ataques de downgrade (si soporta WPA2)"],
    },
}

OUI_DATABASE = {
    "00:17:f2": ("Apple", "Dispositivo Apple"),
    "40:b4:cd": ("Espressif Systems", "Chip ESP8266/ESP32 — IoT (revisar credenciales por defecto)"),
    "00:1a:2b": ("Askey Computer", "Router Movistar — verificar WPS"),
    "54:60:09": ("Huawei", "Router Huawei — revisar admin/admin"),
    "b8:27:eb": ("Raspberry Pi Foundation", "Raspberry Pi"),
    "68:72:51": ("Amazon", "Amazon Echo / Fire TV"),
    "00:15:b9": ("Samsung", "Dispositivo Samsung"),
    "00:1d:0f": ("TP-Link", "Router / dispositivo TP-Link"),
    "50:02:91": ("Tuya Smart", "Dispositivo IoT Tuya"),
}


def get_oui_info(mac: str) -> tuple[str, str]:
    prefix = mac.lower().replace(":", "")[:6]
    formatted_prefix = f"{prefix[0:2]}:{prefix[2:4]}:{prefix[4:6]}"
    return OUI_DATABASE.get(formatted_prefix, ("Desconocido", "Fabricante no identificado"))
