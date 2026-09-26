from datetime import datetime

class AlertEngine:
    def __init__(self):
        self.alerts = []

    def add_alert(self, level: str, message: str, source: str = "system"):
        alert = {
            "id": f"alt_{int(datetime.now().timestamp()*1000)}",
            "level": level,  # INFO, WARNING, HIGH, CRITICAL
            "message": message,
            "source": source,
            "timestamp": datetime.now().isoformat()
        }
        self.alerts.append(alert)
        # Keep only the last 100 alerts
        if len(self.alerts) > 100:
            self.alerts.pop(0)
        return alert

    def analyze_network(self, net: dict) -> list[str]:
        flags = []
        privacy = net.get("privacy", "")
        
        if "OPN" in privacy or privacy == "":
            flags.append("OPEN_NETWORK")
            self.add_alert("CRITICAL", f"Red abierta detectada: {net.get('ssid', 'Oculta')} ({net.get('bssid')})", "scanner")
        if "WEP" in privacy:
            flags.append("WEAK_WEP")
            self.add_alert("CRITICAL", f"Red con WEP detectada: {net.get('ssid', 'Oculta')} ({net.get('bssid')})", "scanner")
        if "WPA-MIGR" in privacy:
            flags.append("LEGACY_WPA")
        if net.get("wps"):
            flags.append("WPS_ENABLED")
            # Avoid spamming WPS alerts, maybe check if it's new
        if net.get("power", -100) > -40:
            flags.append("STRONG_SIGNAL")
        
        return flags

alert_engine = AlertEngine()
