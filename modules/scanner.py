import subprocess
import re
import os
import csv
from datetime import datetime
from modules.knowledge import get_oui_info
from modules.alert_engine import alert_engine

def enable_monitor_mode(interface: str) -> str:
    """Activa el modo monitor y retorna el nombre de la interfaz resultante."""
    subprocess.run(["sudo", "airmon-ng", "check", "kill"], timeout=10)
    result = subprocess.run(
        ["sudo", "airmon-ng", "start", interface],
        capture_output=True, text=True, timeout=15
    )
    match = re.search(r"monitor mode vif enabled.*?(\w+mon)", result.stdout)
    if match:
        return match.group(1)
    
    # Check if a new interface was created anyway (e.g. wlan0mon or similar)
    iwconfig_res = subprocess.run(["iwconfig"], capture_output=True, text=True)
    match_fallback = re.search(rf"({interface}\w*)\s+IEEE", iwconfig_res.stdout)
    if match_fallback:
        return match_fallback.group(1)
    
    return f"{interface}mon"

def disable_monitor_mode(interface: str):
    subprocess.run(["sudo", "airmon-ng", "stop", interface], timeout=15)
    # Restart network manager so we get internet back on wlan0
    subprocess.run(["sudo", "systemctl", "start", "NetworkManager"], timeout=10)

def parse_airodump_csv(csv_path: str) -> tuple[dict, dict]:
    networks = {}
    clients = {}
    
    if not os.path.exists(csv_path):
        return networks, clients

    with open(csv_path, "r", errors="ignore") as f:
        content = f.read()
    
    sections = content.split("\r\n\r\n")
    if len(sections) == 0:
        return networks, clients

    # Parse Networks
    net_lines = sections[0].split("\r\n")
    if len(net_lines) > 2:
        reader = csv.reader(net_lines[2:])
        for row in reader:
            if len(row) < 14:
                continue
            bssid = row[0].strip()
            if not bssid or bssid == "BSSID":
                continue
                
            ssid = row[13].strip()
            power = int(row[8].strip()) if row[8].strip() else -100
            if power == -1: # Airodump sometimes reports -1 for out of range
                power = -100

            oui_name, _ = get_oui_info(bssid)
            
            net_info = {
                "bssid": bssid,
                "first_seen": row[1].strip(),
                "last_seen": row[2].strip(),
                "channel": int(row[3].strip()) if row[3].strip().isdigit() else 0,
                "speed": row[4].strip(),
                "privacy": row[5].strip(),
                "cipher": row[6].strip(),
                "auth": row[7].strip(),
                "power": power,
                "beacons": int(row[9].strip()) if row[9].strip().isdigit() else 0,
                "iv": int(row[10].strip()) if row[10].strip().isdigit() else 0,
                "ssid": ssid,
                "manufacturer": oui_name,
                "clients": [],
                "wps": False # Basic parsing, airodump alone doesn't show WPS easily in CSV, we will fake it or leave for wash
            }
            net_info["flags"] = alert_engine.analyze_network(net_info)
            networks[bssid] = net_info

    # Parse Clients
    if len(sections) > 1:
        client_lines = sections[1].split("\r\n")
        if len(client_lines) > 2:
            reader = csv.reader(client_lines[2:])
            for row in reader:
                if len(row) < 7:
                    continue
                mac = row[0].strip()
                if not mac or mac == "Station MAC":
                    continue
                
                bssid = row[5].strip()
                if bssid == "(not associated)":
                    bssid = None
                    
                probes = [p.strip() for p in row[6:] if p.strip()]
                power = int(row[3].strip()) if row[3].strip() else -100
                if power == -1:
                    power = -100

                oui_name, oui_desc = get_oui_info(mac)
                
                client_info = {
                    "mac": mac,
                    "first_seen": row[1].strip(),
                    "last_seen": row[2].strip(),
                    "power": power,
                    "packets": int(row[4].strip()) if row[4].strip().isdigit() else 0,
                    "ap_bssid": bssid,
                    "probes": probes,
                    "manufacturer": oui_name,
                    "manufacturer_desc": oui_desc,
                    "associated": bssid is not None
                }
                clients[mac] = client_info
                
                # Add client to network
                if bssid and bssid in networks:
                    if mac not in networks[bssid]["clients"]:
                        networks[bssid]["clients"].append(mac)

    return networks, clients
