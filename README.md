# CIBERNAV

Herramienta de auditoría de ciberseguridad para redes de a bordo. Escanea la red de un buque, identifica servicios expuestos y traduce los hallazgos técnicos a un lenguaje que la tripulación entiende, generando un informe en PDF.

Nace de una idea concreta: en muchos buques los datos de navegación (NMEA) y los sistemas de control viajan por redes planas, sin cifrado ni autenticación. CIBERNAV lo demuestra y lo documenta.

## Características

- **Escaneo de red** con nmap y detección de puertos y servicios.
- **Prueba de concepto NMEA**: se conecta a un puerto NMEA por TCP y captura sentencias para demostrar que los datos de navegación circulan en claro.
- **Traductor de hallazgos**: cada puerto o servicio inseguro se explica en lenguaje sencillo, con su severidad y sus implicaciones.
- **Informes en PDF** listos para entregar al armador o al responsable del buque.
- **Interfaz web** (Flask) para lanzar análisis y consultar el histórico.

## Stack

Python · Flask · python-nmap · Scapy · WeasyPrint · SQLite

## Requisitos

- Kali Linux (u otra distribución con `apt`) con `nmap` instalado.
- Python 3.10+

## Instalación

```bash
git clone https://github.com/rikianeiros/cibernav.git
cd cibernav
chmod +x setup.sh
./setup.sh
```

El script instala las dependencias del sistema, crea el entorno virtual y prepara la base de datos.

## Uso

```bash
source venv/bin/activate
sudo python3 app.py
```

Abre el navegador en `http://localhost:5000`, lanza un nuevo análisis indicando la red o el objetivo y consulta el informe generado.

## Aviso legal y de uso ético

CIBERNAV está pensada para **auditorías de seguridad autorizadas** y con fines educativos. Úsala únicamente sobre redes y sistemas de tu propiedad o para los que tengas permiso expreso y por escrito. El uso de esta herramienta contra sistemas ajenos sin autorización es ilegal, y el autor no se hace responsable del mal uso que se le pueda dar.

## Licencia

Distribuido bajo licencia MIT. Consulta el archivo [LICENSE](LICENSE).
