"""
Módulo Traductor
Convierte hallazgos técnicos en explicaciones comprensibles ("Para dummies").
Cubre los puertos más críticos en entornos navales y corporativos.
"""

PUERTOS_COMUNES = {
    # --- Muy críticos ---
    23: {
        "nombre": "Telnet",
        "severidad": "ALTA",
        "explicacion": "Consola de administración antigua que transmite todas las contraseñas en texto plano por la red. Cualquiera que esté escuchando puede verlas.",
        "recomendacion": "Deshabilitar inmediatamente. Reemplazar con SSH (puerto 22)."
    },
    3389: {
        "nombre": "Escritorio Remoto (RDP)",
        "severidad": "ALTA",
        "explicacion": "Permite controlar un PC Windows remotamente. Si la contraseña es débil, un atacante puede tomar el control total del equipo.",
        "recomendacion": "Deshabilitar si no es necesario. Si se usa, requerir contraseña robusta y limitar el acceso por IP."
    },
    5900: {
        "nombre": "VNC (Control Remoto)",
        "severidad": "ALTA",
        "explicacion": "Sistema de control remoto de escritorio. Con frecuencia configurado sin contraseña o con la contraseña de fábrica.",
        "recomendacion": "Deshabilitar si no se usa activamente. Si se usa, configurar una contraseña fuerte."
    },
    10110: {
        "nombre": "NMEA TCP (Datos Náuticos)",
        "severidad": "ALTA",
        "explicacion": "Puerto marítimo estándar que emite datos de navegación en tiempo real (posición GPS, rumbo, velocidad) sin ninguna autenticación.",
        "recomendacion": "Aislar la red náutica de la red de tripulación. Este servicio no debe ser accesible desde la red general."
    },
    2000: {
        "nombre": "NMEA 2000 / Cisco SCCP",
        "severidad": "ALTA",
        "explicacion": "Puede ser el bus de datos NMEA 2000 expuesto en red, lo que permite leer y potencialmente inyectar datos de navegación.",
        "recomendacion": "Verificar qué servicio está corriendo y aislar la red náutica."
    },
    # --- Críticos en contexto ---
    21: {
        "nombre": "FTP (Transferencia de Archivos)",
        "severidad": "ALTA",
        "explicacion": "Servicio de transferencia de archivos que transmite usuario y contraseña en texto plano. Versión antigua e insegura.",
        "recomendacion": "Reemplazar con SFTP (sobre SSH). Verificar que no admite acceso anónimo."
    },
    69: {
        "nombre": "TFTP (Transferencia Trivial)",
        "severidad": "ALTA",
        "explicacion": "Versión ultraligera de FTP sin ningún tipo de autenticación. Cualquiera en la red puede descargar y subir archivos.",
        "recomendacion": "Deshabilitar si no es estrictamente necesario para funciones de la red."
    },
    161: {
        "nombre": "SNMP (Gestión de Red)",
        "severidad": "ALTA",
        "explicacion": "Protocolo de gestión de red. Con la cadena de comunidad por defecto ('public') expone toda la configuración del router o switch.",
        "recomendacion": "Cambiar la cadena de comunidad a una contraseña robusta o deshabilitar si no se gestiona activamente."
    },
    # --- Moderados ---
    22: {
        "nombre": "SSH (Consola Segura)",
        "severidad": "BAJA",
        "explicacion": "Consola de administración remota cifrada. Es segura si las contraseñas son fuertes o se usan llaves criptográficas.",
        "recomendacion": "Verificar que la versión de SSH está actualizada. Considerar deshabilitar el acceso por contraseña y usar solo llaves."
    },
    80: {
        "nombre": "HTTP (Web sin Cifrar)",
        "severidad": "MEDIA",
        "explicacion": "Panel web sin cifrado. Cualquier credencial introducida en esta web puede ser interceptada por cualquier dispositivo en la misma red.",
        "recomendacion": "Migrar a HTTPS (puerto 443). Si es un panel de administración de equipo náutico, cambiar la contraseña por defecto."
    },
    443: {
        "nombre": "HTTPS (Web Cifrada)",
        "severidad": "BAJA",
        "explicacion": "Panel web con cifrado. La comunicación está protegida.",
        "recomendacion": "Verificar que el certificado es válido y que la contraseña de acceso no es la de fábrica."
    },
    8080: {
        "nombre": "HTTP Alternativo (Panel Admin)",
        "severidad": "MEDIA",
        "explicacion": "Panel de administración web en un puerto alternativo. Suelen ser interfaces de routers, cámaras o sistemas de navegación con credenciales por defecto.",
        "recomendacion": "Acceder al panel y cambiar las credenciales de acceso. Migrar a HTTPS si es posible."
    },
    8443: {
        "nombre": "HTTPS Alternativo",
        "severidad": "BAJA",
        "explicacion": "Panel web cifrado en puerto alternativo.",
        "recomendacion": "Verificar que el certificado es válido y cambiar las credenciales por defecto."
    },
    445: {
        "nombre": "SMB (Compartición de Archivos Windows)",
        "severidad": "MEDIA",
        "explicacion": "Servicio de Windows para compartir carpetas en red. Si no está correctamente configurado puede exponer documentos internos.",
        "recomendacion": "Verificar que requiere contraseña para acceder y que no hay carpetas compartidas sin protección."
    },
    139: {
        "nombre": "NetBIOS (Identificación Windows)",
        "severidad": "BAJA",
        "explicacion": "Protocolo de red antiguo de Windows que anuncia el nombre del equipo y del grupo de trabajo en la red.",
        "recomendacion": "Deshabilitar si no es necesario para la red. Revela información del equipo."
    },
    3306: {
        "nombre": "MySQL (Base de Datos)",
        "severidad": "ALTA",
        "explicacion": "Base de datos MySQL expuesta directamente en red. Si acepta conexiones desde cualquier IP, un atacante podría intentar acceder a todos los datos almacenados.",
        "recomendacion": "Limitar el acceso a la base de datos solo a la IP local (127.0.0.1). Nunca debe estar accesible desde la red general."
    },
    5432: {
        "nombre": "PostgreSQL (Base de Datos)",
        "severidad": "ALTA",
        "explicacion": "Base de datos PostgreSQL expuesta en red. Mismo riesgo que MySQL.",
        "recomendacion": "Limitar el acceso a solo conexiones locales."
    },
    27017: {
        "nombre": "MongoDB (Base de Datos)",
        "severidad": "ALTA",
        "explicacion": "Base de datos MongoDB expuesta en red. Históricamente se ha configurado sin contraseña, exponiendo todos los datos.",
        "recomendacion": "Habilitar autenticación y limitar acceso a la IP local."
    },
}

def traducir_puerto(puerto):
    """Devuelve la traducción amigable de un puerto, o un genérico si no se conoce."""
    return PUERTOS_COMUNES.get(puerto, {
        "nombre": f"Servicio no catalogado (Puerto {puerto})",
        "severidad": "MEDIA",
        "explicacion": "Puerto de red abierto cuya función no está en la base de conocimiento. Puede ser un servicio legítimo o una aplicación desconocida.",
        "recomendacion": "Investigar qué aplicación está usando este puerto y evaluar si es necesario que esté abierto."
    })
