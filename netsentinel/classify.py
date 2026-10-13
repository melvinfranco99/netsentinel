"""Clasificación del tipo de dispositivo y estimación del sistema operativo."""

import re

TYPES = {
    "router": "Router / Gateway", "ap": "Punto de acceso / Red", "pc": "Ordenador",
    "server": "Servidor", "laptop": "Portátil", "phone": "Móvil / Tablet",
    "printer": "Impresora", "tv": "TV / Multimedia", "speaker": "Altavoz inteligente",
    "camera": "Cámara IP", "iot": "IoT / Domótica", "nas": "NAS / Almacenamiento",
    "console": "Consola", "vm": "Máquina virtual", "this": "Este equipo", "unknown": "Desconocido",
}

VENDOR_RULES = [
    (r"mikrotik|routerboard|ubiquiti|netgear|tp-?link|d-?link|zyxel|cisco|juniper|arris|"
     r"sagemcom|technicolor|askey|avm|fritz|mitrastar|zte|huawei|nokia|sercomm|tenda|"
     r"linksys|aruba|ruckus|cambium|eero|draytek|fortinet|sophos|watchguard|xiaomi.*router", "router"),
    (r"hewlett|hp inc|epson|canon|brother|lexmark|kyocera|ricoh|xerox|konica|sharp corp", "printer"),
    (r"hikvision|dahua|axis comm|reolink|amcrest|foscam|wyze|ezviz|uniview|hanwha", "camera"),
    (r"synology|qnap|western digital|buffalo|asustor|drobo|terramaster", "nas"),
    (r"espressif|tuya|shelly|sonoff|itead|lifx|philips lighting|signify|ring|nest|"
     r"tado|netatmo|broadlink|yeelight|meross|wiz|xiaomi|lumi|aqara|silicon labs|murata", "iot"),
    (r"sonos|bose|amazon|google|harman", "speaker"),
    (r"samsung elec.*visual|lg electronics|roku|tcl|hisense|vizio|nvidia|sony|panasonic|philips", "tv"),
    (r"nintendo|sony interactive|microsoft.*xbox", "console"),
    (r"apple", "phone"), (r"samsung|oneplus|oppo|vivo|motorola|realme|honor|nothing", "phone"),
    (r"raspberry", "server"),
    (r"vmware|virtualbox|qemu|xen|parallels|microsoft corporation.*hyper", "vm"),
    (r"intel|realtek|dell|lenovo|asustek|gigabyte|micro-star|msi|acer|hon hai|liteon|azurewave|"
     r"ralink|qualcomm|broadcom|mediatek|chicony", "pc"),
]

PORT_RULES = [
    ({9100, 631, 515}, "printer"), ({554, 8554, 37777, 34567}, "camera"), ({62078}, "phone"),
    ({8291, 8728, 7547}, "router"), ({8009, 8008}, "tv"), ({1400}, "speaker"), ({8060}, "tv"),
    ({5000, 5001}, "nas"), ({548}, "nas"), ({3389, 135}, "pc"), ({1883, 8123, 6668}, "iot"),
    ({5555}, "tv"), ({32400}, "server"),
]

MDNS_RULES = [
    ("ipp", "printer"), ("printer", "printer"), ("pdl-datastream", "printer"), ("uscan", "printer"),
    ("googlecast", "tv"), ("airplay", "tv"), ("raop", "speaker"), ("spotify-connect", "speaker"),
    ("sonos", "speaker"), ("amzn-wplay", "speaker"), ("androidtvremote2", "tv"), ("hap", "iot"),
    ("homekit", "iot"), ("matter", "iot"), ("esphomelib", "iot"), ("hue", "iot"),
    ("companion-link", "phone"), ("apple-mobdev2", "phone"), ("smb", "pc"), ("afpovertcp", "nas"),
    ("workstation", "pc"), ("home-assistant", "server"), ("nvstream", "pc"),
]


def classify(h: dict, gateway: str | None, self_ip: str | None) -> tuple[str, str]:
    """Devuelve (tipo, motivo)."""
    if h["ip"] == self_ip:
        return "this", "IP de este equipo"
    if h["ip"] == gateway:
        return "router", "Puerta de enlace predeterminada"
    ports = {s["port"] for s in h.get("services", [])}
    upnp = h.get("upnp") or {}
    dtype = (upnp.get("device_type") or "") + " " + " ".join(upnp.get("types", []))
    if "InternetGatewayDevice" in dtype:
        return "router", "UPnP InternetGatewayDevice"
    if "MediaRenderer" in dtype:
        return "tv", "UPnP MediaRenderer"
    if "Printer" in dtype:
        return "printer", "UPnP Printer"
    for svc in h.get("mdns", {}).get("services", []):
        for key, t in MDNS_RULES:
            if svc["type"] == key:
                return t, f"Servicio mDNS _{key}"
    for pset, t in PORT_RULES:
        if ports & pset:
            return t, f"Puerto {sorted(ports & pset)[0]} abierto"
    for s in h.get("services", []):
        app = ((s.get("http") or {}).get("app") or "") + " " + (s.get("product") or "")
        if re.search(r"RouterOS|OpenWrt|pfSense|OPNsense|FRITZ|ZTE|Huawei|TP-Link|UniFi", app, re.I):
            return "router", f"Panel web: {app.strip()}"
        if re.search(r"HP Embedded|Epson|Brother", app, re.I):
            return "printer", app.strip()
        if re.search(r"Synology|QNAP", app, re.I):
            return "nas", app.strip()
        if re.search(r"Hikvision|Dahua", app, re.I):
            return "camera", app.strip()
    vendor = (h.get("vendor") or "").lower()
    for rx, t in VENDOR_RULES:
        if re.search(rx, vendor):
            # ZTE/Huawei también fabrican móviles: solo es router si tiene panel web o DNS
            if t == "router" and not (ports & {53, 80, 443, 8080, 1900}) and not upnp:
                if re.search(r"zte|huawei|xiaomi", vendor):
                    return "phone", f"Fabricante {h.get('vendor')}"
            if t == "router" and h["ip"] != gateway:
                return "ap", f"Fabricante {h.get('vendor')}"
            return t, f"Fabricante {h.get('vendor')}"
    if h.get("random_mac"):
        return "phone", "MAC aleatoria (privacidad de iOS/Android/Windows)"
    if ports & {22} and h.get("ttl", 0) and h["ttl"] <= 64:
        return "server", "SSH abierto, TTL Unix"
    if ports & {445, 139}:
        return "pc", "Compartición de archivos Windows"
    return "unknown", ""


def guess_os(h: dict) -> str:
    banners = " ".join((s.get("banner") or "") + " " + (s.get("product") or "") + " " +
                       ((s.get("http") or {}).get("server") or "") for s in h.get("services", []))
    snmp = (h.get("udp", {}).get("snmp") or {}).get("sysdescr", "")
    txt = (banners + " " + snmp + " " + (h.get("upnp") or {}).get("server", "")).lower()
    for rx, name in (
        (r"routeros|mikrotik", "MikroTik RouterOS"), (r"windows|microsoft-iis|microsoft-httpapi", "Windows"),
        (r"ubuntu", "Linux (Ubuntu)"), (r"debian", "Linux (Debian)"), (r"raspbian", "Linux (Raspberry Pi OS)"),
        (r"fedora|red ?hat|centos|rocky|alma", "Linux (RHEL/Fedora)"), (r"arch", "Linux (Arch)"),
        (r"openwrt|lede", "OpenWrt"), (r"synology|dsm", "Synology DSM"), (r"freebsd", "FreeBSD"),
        (r"darwin|mac os|macos", "macOS"), (r"android", "Android"), (r"cisco ios", "Cisco IOS"),
        (r"linux", "Linux"), (r"dropbear", "Linux embebido"),
    ):
        if re.search(rx, txt):
            return name
    mdns = h.get("mdns", {})
    if mdns.get("txt", {}).get("osxvers") or any(s["type"] in ("companion-link", "apple-mobdev2", "airplay")
                                                 for s in mdns.get("services", [])):
        return "Apple (iOS/macOS)"
    vendor = (h.get("vendor") or "").lower()
    if "apple" in vendor:
        return "Apple (iOS/macOS)"
    ports = {s["port"] for s in h.get("services", [])}
    if ports & {135, 3389, 5985}:
        return "Windows"
    ttl = h.get("ttl")
    if ttl:
        if ttl > 128:
            return "Equipo de red / embebido (TTL 255)"
        if ttl > 64:
            return "Windows (TTL 128)"
        return "Linux / Unix / Android / iOS (TTL 64)"
    return ""
