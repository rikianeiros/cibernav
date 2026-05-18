import nmap
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ScannerNmap:
    def __init__(self):
        try:
            self.nm = nmap.PortScanner()
        except nmap.PortScannerError:
            logger.error("Nmap no encontrado. Asegúrate de instalar nmap en el sistema (apt install nmap).")
            raise
    
    def scan_network(self, target, arguments="-sS -sV -O --top-ports 100"):
        """
        Realiza un escaneo de nmap sobre el objetivo.
        Retorna una lista de diccionarios con la información estructurada por host.
        Nota: '-O' y '-sS' requieren ejecución con sudo.
        """
        logger.info(f"Iniciando escaneo nmap en {target} con args: {arguments}")
        try:
            self.nm.scan(hosts=target, arguments=arguments)
            resultados = []
            
            for host in self.nm.all_hosts():
                if self.nm[host].state() != 'up':
                    continue
                
                info_host = {
                    "ip": host,
                    "hostname": self.nm[host].hostname(),
                    "mac": "Desconocida",
                    "vendor": "Desconocido",
                    "os": "Desconocido",
                    "puertos": []
                }
                
                # Extraer MAC (Solo funciona si escaneamos en la misma subred LAN)
                if 'mac' in self.nm[host]['addresses']:
                    info_host["mac"] = self.nm[host]['addresses']['mac']
                    if 'vendor' in self.nm[host] and info_host["mac"] in self.nm[host]['vendor']:
                        info_host["vendor"] = self.nm[host]['vendor'][info_host["mac"]]
                
                # Extraer Sistema Operativo (Requiere sudo)
                if 'osmatch' in self.nm[host] and len(self.nm[host]['osmatch']) > 0:
                    info_host["os"] = self.nm[host]['osmatch'][0]['name']
                    
                # Extraer Puertos Abiertos TCP
                if 'tcp' in self.nm[host]:
                    for puerto in self.nm[host]['tcp']:
                        estado = self.nm[host]['tcp'][puerto]['state']
                        if estado == 'open':
                            producto = self.nm[host]['tcp'][puerto].get('product', '')
                            version = self.nm[host]['tcp'][puerto].get('version', '')
                            version_completa = f"{producto} {version}".strip()
                            info_puerto = {
                                "puerto": puerto,
                                "protocolo": "tcp",
                                "servicio": self.nm[host]['tcp'][puerto].get('name', 'desconocido'),
                                "version": version_completa
                            }
                            info_host["puertos"].append(info_puerto)

                # Extraer Puertos Abiertos UDP (si el escaneo los incluyó)
                if 'udp' in self.nm[host]:
                    for puerto in self.nm[host]['udp']:
                        estado = self.nm[host]['udp'][puerto]['state']
                        if estado in ('open', 'open|filtered'):
                            producto = self.nm[host]['udp'][puerto].get('product', '')
                            version = self.nm[host]['udp'][puerto].get('version', '')
                            version_completa = f"{producto} {version}".strip()
                            info_puerto = {
                                "puerto": puerto,
                                "protocolo": "udp",
                                "servicio": self.nm[host]['udp'][puerto].get('name', 'desconocido'),
                                "version": version_completa
                            }
                            info_host["puertos"].append(info_puerto)
                            
                resultados.append(info_host)
                
            return resultados
        except Exception as e:
            logger.error(f"Error crítico en escaneo nmap: {e}")
            return None

if __name__ == '__main__':
    print("[*] Probando Scanner Nmap (Escaneo rápido a localhost)")
    scanner = ScannerNmap()
    # Usamos puertos específicos sin OS para no requerir sudo en esta prueba simple
    res = scanner.scan_network("127.0.0.1", arguments="-p 22,80,443 -sV")
    import json
    print(json.dumps(res, indent=4))
