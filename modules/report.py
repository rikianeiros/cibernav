"""
Generación de informes.

Toma un escaneo guardado en la base de datos, enriquece cada servicio con la
base de conocimiento y produce un informe. Si WeasyPrint está disponible
genera un PDF; si no, devuelve el HTML equivalente (degradación elegante).
"""
import os
from datetime import datetime

from jinja2 import Environment, FileSystemLoader, select_autoescape

from config import BASE_DIR, REPORTS_DIR
from modules.knowledge import get_port_knowledge

_env = Environment(
    loader=FileSystemLoader(os.path.join(BASE_DIR, "templates")),
    autoescape=select_autoescape(["html", "xml"]),
)

_RISK_RANK = {"CRÍTICO": 4, "ALTO": 3, "MEDIO-ALTO": 3, "MEDIO": 2, "BAJO": 1, "DESCONOCIDO": 2}


def _enriquecer(scan: dict) -> dict:
    """Añade la ficha de conocimiento a cada servicio y calcula estadísticas."""
    total_servicios = 0
    max_riesgo = "BAJO"
    for host in scan.get("hosts", []):
        for serv in host.get("servicios", []):
            total_servicios += 1
            k = get_port_knowledge(serv["puerto"], serv.get("servicio", ""))
            serv["knowledge"] = k
            if _RISK_RANK.get(k["riesgo"], 0) > _RISK_RANK.get(max_riesgo, 0):
                max_riesgo = k["riesgo"]
    scan["total_dispositivos"] = len(scan.get("hosts", []))
    scan["total_servicios"] = total_servicios
    scan["riesgo_global"] = max_riesgo if total_servicios else "N/A"
    return scan


def render_html(scan: dict) -> str:
    scan = _enriquecer(scan)
    template = _env.get_template("report.html")
    return template.render(scan=scan, generado=datetime.now().strftime("%Y-%m-%d %H:%M"))


def generar_informe(scan: dict) -> dict:
    """
    Devuelve {'formato': 'pdf'|'html', 'ruta': ..., 'contenido': ...}.
    En PDF escribe el fichero en REPORTS_DIR y devuelve su ruta.
    En HTML devuelve el contenido para servirlo directamente.
    """
    html = render_html(scan)
    try:
        from weasyprint import HTML  # import perezoso: puede no estar instalado
        nombre = f"informe_{scan.get('objetivo', 'objetivo')}_{scan.get('id')}.pdf".replace(" ", "_")
        ruta = os.path.join(REPORTS_DIR, nombre)
        HTML(string=html).write_pdf(ruta)
        return {"formato": "pdf", "ruta": ruta, "contenido": None}
    except Exception:
        return {"formato": "html", "ruta": None, "contenido": html}
