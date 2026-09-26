# CIBERNAV

Suite web de auditoría de seguridad de redes **Wi-Fi, IoT y entornos náuticos**. Reúne en una sola interfaz el reconocimiento de redes, el escaneo de puertos, los ataques inalámbricos de auditoría y la generación de informes, y traduce cada hallazgo técnico a un lenguaje claro para quien no es especialista.

Construida sobre FastAPI, con actualizaciones en tiempo real por WebSocket. Está diseñada para **degradar con elegancia**: en un equipo sin las herramientas de Kali o sin antena en modo monitor, las funciones de análisis pasivo (nmap, NMEA, informes) siguen disponibles y solo se desactiva lo que depende del hardware ausente.

## Características

### Reconocimiento y ataque Wi-Fi
- Activación de **modo monitor** y **escaneo en tiempo real** de redes y clientes (airodump-ng).
- Detección de redes **abiertas**, con **WPS** activo y su tipo de cifrado (OPN/WEP/WPA/WPA2/WPA3), con el riesgo explicado.
- Identificación de fabricante por **MAC (OUI)**: señala ESP32, cámaras IP, routers con credenciales por defecto, etc.
- Ataques de auditoría: **deauth**, captura de **handshake WPA/WPA2** y **PMKID** (hcxdumptool), con salida en vivo.
- **Crackeo por diccionario** de las capturas obtenidas: aircrack-ng (handshakes) y hashcat (PMKID), con recuperación de la clave si está en la lista.

### Análisis de host
- Escaneo de puertos con **nmap** (perfiles rápido / estándar / completo).
- Cada servicio se traduce a: qué es, nivel de riesgo, implicaciones y recomendación.

### Inventario e informes
- Escaneo de inventario por **objetivo** (una casa, una oficina, un buque) con persistencia en SQLite.
- **Informe ejecutivo** en PDF (o HTML si WeasyPrint no está disponible), presentable para un cliente.

### Modo naval (NMEA)
- Prueba de concepto que comprueba si los **datos de navegación** (posición GPS, rumbo, velocidad) viajan en claro por la red, sin cifrado ni autenticación.

## Stack

Python · FastAPI · Uvicorn · WebSockets · python-nmap · aircrack-ng · hcxdumptool · bettercap · WeasyPrint · SQLite

## Requisitos

- **Recomendado:** Kali Linux (o Debian) con las herramientas de auditoría instaladas.
- Adaptador Wi-Fi con soporte de **modo monitor** (probado con Alfa AWUS036ACH / driver `88xxau`) para el reconocimiento y los ataques inalámbricos.
- Python 3.10+
- El análisis (nmap, NMEA, informes) funciona en cualquier equipo, incluido macOS, sin la antena.

## Instalación

```bash
git clone https://github.com/rikianeiros/cibernav.git
cd cibernav
chmod +x setup.sh run.sh
./setup.sh        # instala dependencias del sistema (si hay apt) y el entorno Python
```

## Configuración

Copia `.env.example` a `.env` y define al menos las credenciales del panel:

```bash
CIBERNAV_USER=admin
CIBERNAV_PASS=una-contrasena-que-elijas-tu
```

Si no defines `CIBERNAV_PASS`, la app genera una contraseña aleatoria por sesión y la muestra por consola al arrancar. **Nunca hay credenciales fijas en el repositorio.**

## Uso

```bash
./run.sh
```

Abre el navegador en `http://127.0.0.1:8080`. El panel muestra al arrancar las **capacidades disponibles** en tu equipo y avisa de lo que falte.

## Aviso legal y de uso ético

CIBERNAV es una herramienta de **auditoría de seguridad y aprendizaje**. Utilízala exclusivamente sobre redes y dispositivos de tu propiedad o para los que dispongas de **autorización expresa y por escrito**. Interceptar tráfico o atacar redes ajenas sin permiso es ilegal. El autor no se responsabiliza del uso indebido de esta herramienta.

## Licencia

Distribuido bajo licencia MIT. Consulta el archivo [LICENSE](LICENSE).
