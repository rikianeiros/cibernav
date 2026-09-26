import nmap
import asyncio
from modules.knowledge import PORT_KNOWLEDGE

class NmapScanner:
    def __init__(self):
        # Construcción tolerante: si el binario nmap no está instalado, la app
        # sigue arrancando y esta capacidad queda desactivada hasta instalarlo.
        self.nm = None
        try:
            self.nm = nmap.PortScanner()
        except Exception:
            self.nm = None

    def _ensure(self):
        if self.nm is None:
            self.nm = nmap.PortScanner()  # relanza el error legible si sigue sin estar
        return self.nm

    async def scan(self, target_ip: str, profile: str = "rápido") -> list[dict]:
        self._ensure()
        args = "-F -T4"
        if profile == "estándar":
            args = "-sV -T4"
        elif profile == "completo":
            args = "-sV -p- -T3"

        # Escaneo bloqueante, usar run_in_executor para no bloquear el loop asíncrono
        loop = asyncio.get_event_loop()
        try:
            await loop.run_in_executor(None, lambda: self.nm.scan(target_ip, arguments=args))
        except Exception as e:
            return [{"error": str(e)}]

        if target_ip not in self.nm.all_hosts():
            return []

        results = []
        for proto in self.nm[target_ip].all_protocols():
            if proto != 'tcp': continue
            
            ports = self.nm[target_ip][proto].keys()
            for port in sorted(ports):
                state = self.nm[target_ip][proto][port]['state']
                if state != 'open': continue

                service = self.nm[target_ip][proto][port].get('name', 'unknown')
                version = self.nm[target_ip][proto][port].get('version', '')
                
                knowledge = PORT_KNOWLEDGE.get(port, {
                    "servicio": f"{service}",
                    "riesgo": "DESCONOCIDO",
                    "descripcion": "Puerto abierto sin información específica.",
                    "implicaciones": ["Investigar manualmente"],
                    "recomendacion": "Verificar si es necesario.",
                })

                results.append({
                    "port": port,
                    "state": state,
                    "service": service,
                    "version": version,
                    "knowledge": knowledge
                })

        return results

    async def scan_inventory(self, target: str, with_os: bool = False) -> list[dict]:
        """
        Escaneo de red completo que devuelve un inventario por host, en el
        formato que espera la base de datos y los informes:
        {ip, hostname, mac, vendor, os, puertos:[{puerto,protocolo,servicio,version}]}

        `with_os` activa detección de SO y SYN scan (requieren sudo). Si no,
        usa un escaneo de servicios estándar que funciona sin privilegios.
        """
        self._ensure()
        args = "-sS -sV -O --top-ports 100" if with_os else "-sV --top-ports 100 -T4"
        loop = asyncio.get_event_loop()
        try:
            await loop.run_in_executor(None, lambda: self.nm.scan(hosts=target, arguments=args))
        except Exception as e:
            return [{"error": str(e)}]

        resultados = []
        for host in self.nm.all_hosts():
            if self.nm[host].state() != "up":
                continue
            info = {"ip": host, "hostname": self.nm[host].hostname(),
                    "mac": "Desconocida", "vendor": "Desconocido", "os": "Desconocido", "puertos": []}
            addrs = self.nm[host].get("addresses", {})
            if "mac" in addrs:
                info["mac"] = addrs["mac"]
                vendor = self.nm[host].get("vendor", {})
                if info["mac"] in vendor:
                    info["vendor"] = vendor[info["mac"]]
            osmatch = self.nm[host].get("osmatch", [])
            if osmatch:
                info["os"] = osmatch[0].get("name", "Desconocido")
            for proto in ("tcp", "udp"):
                if proto not in self.nm[host]:
                    continue
                for port in self.nm[host][proto]:
                    pdata = self.nm[host][proto][port]
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
