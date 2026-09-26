import nmap
import asyncio
from modules.knowledge import PORT_KNOWLEDGE
from modules.vulns import match_cves, parse_vulners

class NmapScanner:
    def __init__(self):
        # Construcción tolerante: si el binario nmap no está instalado, la app
        # sigue arrancando y esta capacidad queda desactivada hasta instalarlo.
        self.available = False
        try:
            nmap.PortScanner()
            self.available = True
        except Exception:
            self.available = False

    def _new(self):
        # Una instancia nueva por escaneo: python-nmap guarda el resultado en el
        # propio objeto, así que compartirlo entre escaneos concurrentes los
        # corrompería. Crear uno por llamada evita esa condición de carrera.
        return nmap.PortScanner()

    async def scan(self, target_ip: str, profile: str = "rápido", vulners: bool = False) -> list[dict]:
        nm = self._new()
        args = "-F -T4"
        if profile == "estándar":
            args = "-sV -T4"
        elif profile == "completo":
            args = "-sV -p- -T3"
        # vulners necesita versiones (-sV) e Internet; añade el script NSE.
        if vulners:
            if "-sV" not in args:
                args += " -sV"
            args += " --script vulners"

        # Escaneo bloqueante, usar run_in_executor para no bloquear el loop asíncrono
        loop = asyncio.get_event_loop()
        try:
            await loop.run_in_executor(None, lambda: nm.scan(target_ip, arguments=args))
        except Exception as e:
            return [{"error": str(e)}]

        if target_ip not in nm.all_hosts():
            return []

        results = []
        for proto in nm[target_ip].all_protocols():
            if proto != 'tcp': continue
            
            ports = nm[target_ip][proto].keys()
            for port in sorted(ports):
                state = nm[target_ip][proto][port]['state']
                if state != 'open': continue

                pdata = nm[target_ip][proto][port]
                service = pdata.get('name', 'unknown')
                banner = f"{pdata.get('product', '')} {pdata.get('version', '')}".strip()

                knowledge = PORT_KNOWLEDGE.get(port, {
                    "servicio": f"{service}",
                    "riesgo": "DESCONOCIDO",
                    "descripcion": "Puerto abierto sin información específica.",
                    "implicaciones": ["Investigar manualmente"],
                    "recomendacion": "Verificar si es necesario.",
                })

                item = {
                    "port": port,
                    "state": state,
                    "service": service,
                    "version": banner,
                    "knowledge": knowledge,
                    "cves": match_cves(service, banner),
                }
                if vulners:
                    script_out = pdata.get("script", {}).get("vulners", "")
                    item["vulners"] = parse_vulners(script_out)
                results.append(item)

        return results

    async def scan_inventory(self, target: str, with_os: bool = False) -> list[dict]:
        """
        Escaneo de red completo que devuelve un inventario por host, en el
        formato que espera la base de datos y los informes:
        {ip, hostname, mac, vendor, os, puertos:[{puerto,protocolo,servicio,version}]}

        `with_os` activa detección de SO y SYN scan (requieren sudo). Si no,
        usa un escaneo de servicios estándar que funciona sin privilegios.
        """
        nm = self._new()
        args = "-sS -sV -O --top-ports 100" if with_os else "-sV --top-ports 100 -T4"
        loop = asyncio.get_event_loop()
        try:
            await loop.run_in_executor(None, lambda: nm.scan(hosts=target, arguments=args))
        except Exception as e:
            return [{"error": str(e)}]

        resultados = []
        for host in nm.all_hosts():
            if nm[host].state() != "up":
                continue
            info = {"ip": host, "hostname": nm[host].hostname(),
                    "mac": "Desconocida", "vendor": "Desconocido", "os": "Desconocido", "puertos": []}
            addrs = nm[host].get("addresses", {})
            if "mac" in addrs:
                info["mac"] = addrs["mac"]
                vendor = nm[host].get("vendor", {})
                if info["mac"] in vendor:
                    info["vendor"] = vendor[info["mac"]]
            osmatch = nm[host].get("osmatch", [])
            if osmatch:
                info["os"] = osmatch[0].get("name", "Desconocido")
            for proto in ("tcp", "udp"):
                if proto not in nm[host]:
                    continue
                for port in nm[host][proto]:
                    pdata = nm[host][proto][port]
                    if pdata.get("state") not in ("open", "open|filtered"):
                        continue
                    version = f"{pdata.get('product', '')} {pdata.get('version', '')}".strip()
                    info["puertos"].append({
                        "puerto": port, "protocolo": proto,
                        "servicio": pdata.get("name", "desconocido"), "version": version,
                    })
            resultados.append(info)
        return resultados


nmap_scanner = NmapScanner()
