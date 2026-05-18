from flask import Flask, render_template, request, redirect, url_for, send_file, jsonify
import io
import os
import re
import threading
import uuid

try:
    from weasyprint import HTML
except ImportError:
    HTML = None

from core.database import get_connection, init_db
from core.scanner_nmap import ScannerNmap
from core.db_manager import DBManager
from core.traductor import traducir_puerto

app = Flask(__name__, template_folder='web/templates', static_folder='web/static')

# --- Inicialización segura de la base de datos ---
# Se crea la carpeta db/ si no existe y se inicializa el schema.
os.makedirs('db', exist_ok=True)
init_db()

db_manager = DBManager()

# El scanner se inicializa de forma lazy para no crashear Flask si nmap no está instalado.
_scanner = None

def get_scanner():
    global _scanner
    if _scanner is None:
        try:
            _scanner = ScannerNmap()
        except Exception as e:
            return None, str(e)
    return _scanner, None

# --- Almacén en memoria para el estado de los escaneos en curso ---
# { job_id: {"estado": "en_curso"|"completado"|"error", "escaneo_id": X, "error": ""} }
escaneos_en_curso = {}

def _patron_ip_valido(objetivo):
    """Valida que el objetivo sea una IP o rango CIDR básico."""
    patron = r'^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$'
    return re.match(patron, objetivo) is not None

def _lanzar_escaneo_fondo(job_id, buque, objetivo):
    """Función que corre en un hilo separado para no bloquear Flask."""
    scanner, err = get_scanner()
    if not scanner:
        escaneos_en_curso[job_id] = {"estado": "error", "error": f"Nmap no disponible: {err}"}
        return
    
    resultados = scanner.scan_network(objetivo)
    if resultados is not None:
        escaneo_id = db_manager.procesar_resultados_nmap(buque, resultados)
        if escaneo_id is None:
            # Escaneo OK pero red vacía (ningún host activo encontrado)
            escaneo_id = db_manager.crear_escaneo(db_manager.registrar_buque(buque), tipo="Nmap Vacío")
        escaneos_en_curso[job_id] = {"estado": "completado", "escaneo_id": escaneo_id}
    else:
        escaneos_en_curso[job_id] = {"estado": "error", "error": "El escaneo no devolvió resultados. Comprueba la IP y que tienes permisos (sudo)."}

# --- Rutas Flask ---

@app.route('/')
def index():
    with get_connection() as conn:
        c = conn.cursor()
        c.execute("""
            SELECT b.id, b.nombre, b.fecha_registro, COUNT(e.id) as num_escaneos
            FROM buques b
            LEFT JOIN escaneos e ON b.id = e.buque_id
            GROUP BY b.id
            ORDER BY b.fecha_registro DESC
        """)
        buques = c.fetchall()
    return render_template('index.html', buques=buques)

@app.route('/buque/<int:buque_id>')
def ver_buque(buque_id):
    """Lista todos los escaneos de un buque concreto."""
    with get_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT * FROM buques WHERE id = ?", (buque_id,))
        buque = c.fetchone()
        if not buque:
            return "Buque no encontrado", 404
        c.execute("SELECT * FROM escaneos WHERE buque_id = ? ORDER BY fecha DESC", (buque_id,))
        escaneos = c.fetchall()
    return render_template('buque.html', buque=buque, escaneos=escaneos)

@app.route('/nuevo_analisis', methods=['GET', 'POST'])
def nuevo_analisis():
    error = None
    if request.method == 'POST':
        buque = request.form.get('buque', '').strip()
        objetivo = request.form.get('objetivo', '').strip()

        # Validación de input
        if not buque:
            error = "El nombre del buque no puede estar vacío."
        elif not objetivo:
            error = "El objetivo de red no puede estar vacío."
        elif not _patron_ip_valido(objetivo):
            error = f"'{objetivo}' no es una dirección IP o rango CIDR válido. Ejemplo: 192.168.1.0/24"
        else:
            # Lanzar escaneo en hilo de fondo
            job_id = str(uuid.uuid4())
            escaneos_en_curso[job_id] = {"estado": "en_curso"}
            hilo = threading.Thread(target=_lanzar_escaneo_fondo, args=(job_id, buque, objetivo), daemon=True)
            hilo.start()
            return redirect(url_for('estado_escaneo', job_id=job_id))

    return render_template('nuevo_analisis.html', error=error)

@app.route('/estado/<job_id>')
def estado_escaneo(job_id):
    """Página de espera que informa del estado del escaneo en curso."""
    return render_template('estado_escaneo.html', job_id=job_id)

@app.route('/api/estado/<job_id>')
def api_estado_escaneo(job_id):
    """Endpoint JSON que el JS de la página de espera consulta periódicamente."""
    estado = escaneos_en_curso.get(job_id, {"estado": "no_encontrado"})
    return jsonify(estado)

def _obtener_datos_escaneo(escaneo_id):
    """Función helper para obtener los datos estructurados y traducidos de un escaneo."""
    conn = None
    try:
        conn = get_connection()
        c = conn.cursor()
        c.execute("""
            SELECT e.*, b.nombre as buque_nombre
            FROM escaneos e
            JOIN buques b ON e.buque_id = b.id
            WHERE e.id = ?
        """, (escaneo_id,))
        escaneo = c.fetchone()
        if not escaneo:
            return None, None
        c.execute("""
            SELECT a.id, a.ip, a.hostname, a.os_detectado, d.mac, d.fabricante
            FROM avistamientos a
            JOIN dispositivos d ON a.dispositivo_id = d.id
            WHERE a.escaneo_id = ?
        """, (escaneo_id,))
        avistamientos = c.fetchall()
        resultados_completos = []
        for av in avistamientos:
            c.execute("SELECT * FROM servicios WHERE avistamiento_id = ?", (av['id'],))
            servicios = c.fetchall()
            servicios_traducidos = []
            for serv in servicios:
                serv_dict = dict(serv)
                serv_dict['traduccion'] = traducir_puerto(serv_dict['puerto'])
                servicios_traducidos.append(serv_dict)
            # Limpiar MAC interna NO_MAC_ para mostrar al usuario
            av_dict = dict(av)
            if av_dict.get('mac', '').startswith('NO_MAC_'):
                av_dict['mac'] = 'No disponible (host remoto)'
            resultados_completos.append({
                "info": av_dict,
                "servicios": servicios_traducidos
            })
        return dict(escaneo), resultados_completos
    finally:
        if conn is not None:
            conn.close()

@app.route('/escaneo/<int:escaneo_id>')
def ver_escaneo(escaneo_id):
    escaneo, resultados_completos = _obtener_datos_escaneo(escaneo_id)
    if not escaneo:
        return "Escaneo no encontrado", 404
    return render_template('escaneo.html', escaneo=escaneo, resultados=resultados_completos)

@app.route('/descargar_pdf/<int:escaneo_id>')
def descargar_pdf(escaneo_id):
    if HTML is None:
        return "Error: WeasyPrint no está instalado. Ejecuta setup.sh de nuevo.", 500
    escaneo, resultados_completos = _obtener_datos_escaneo(escaneo_id)
    if not escaneo:
        return "Escaneo no encontrado", 404
    html_renderizado = render_template('reporte_pdf.html', escaneo=escaneo, resultados=resultados_completos)
    pdf_buffer = io.BytesIO()
    HTML(string=html_renderizado).write_pdf(pdf_buffer)
    pdf_buffer.seek(0)
    nombre_archivo = f"Auditoria_CIBERNAV_{escaneo['buque_nombre'].replace(' ', '_')}.pdf"
    return send_file(pdf_buffer, as_attachment=True, download_name=nombre_archivo, mimetype='application/pdf')

@app.route('/inteligencia')
def inteligencia():
    with get_connection() as conn:
        c = conn.cursor()
        c.execute("""
            SELECT d.mac, d.fabricante, COUNT(DISTINCT e.buque_id) as num_buques,
                   GROUP_CONCAT(DISTINCT b.nombre) as buques_visitados
            FROM dispositivos d
            JOIN avistamientos a ON d.id = a.dispositivo_id
            JOIN escaneos e ON a.escaneo_id = e.id
            JOIN buques b ON e.buque_id = b.id
            WHERE d.mac NOT LIKE 'NO_MAC_%' AND d.mac != 'Desconocida'
            GROUP BY d.mac
            HAVING num_buques > 1
            ORDER BY num_buques DESC
        """)
        macs_repetidas = c.fetchall()
    return render_template('inteligencia.html', macs=macs_repetidas)

if __name__ == '__main__':
    print("[*] Iniciando CIBERNAV Dashboard (Puerto 5000)")
    app.run(host='0.0.0.0', port=5000, debug=False)
