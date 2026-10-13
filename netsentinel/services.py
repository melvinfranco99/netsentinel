"""Escaneo de puertos TCP y detección de servicio/versión."""

import asyncio
import html
import re
import time

from . import probes
from .netio import TCPConn, http_get, parse_http
from .ports import service_name

HTTP_PORTS = {80, 81, 443, 591, 3000, 5000, 5001, 5357, 7080, 7443, 8000, 8008, 8080, 8081,
              8088, 8089, 8123, 8181, 8443, 8888, 9000, 9080, 9090, 9443, 10000, 10443,
              49152, 52868, 631, 9200, 2375, 2376, 15672, 5601, 4443, 1400, 8060, 7547, 32400}
TLS_PORTS = {443, 465, 563, 636, 853, 989, 990, 992, 993, 994, 995, 2376, 3269, 4443, 5001,
             5986, 6443, 7443, 8443, 8729, 8883, 9443, 10443, 10250, 631}
BANNER_PORTS = {21, 22, 23, 25, 110, 143, 220, 587, 2222, 2323, 3306, 5900, 5901, 6667}


async def scan_ports(ip: str, ports: list[int], sem: asyncio.Semaphore,
                     timeout: float = 1.0, on_progress=None, cancel=None) -> list[dict]:
    opened = []

    async def one(p):
        if cancel and cancel.is_set():
            return
        async with sem:
            t0 = time.monotonic()
            try:
                r, w = await asyncio.wait_for(asyncio.open_connection(ip, p), timeout)
                opened.append({"port": p, "rtt": round((time.monotonic() - t0) * 1000, 1)})
                w.close()
            except (OSError, asyncio.TimeoutError, TimeoutError):
                pass
            finally:
                if on_progress:
                    on_progress(1)

    await asyncio.gather(*(one(p) for p in ports))
    return sorted(opened, key=lambda x: x["port"])


# ----------------------------------------------------------- Firmas -------
SIGS = [
    # (regex sobre banner, servicio, producto, grupo-versión)
    (r"^SSH-[\d.]+-OpenSSH_([\w.]+)", "ssh", "OpenSSH", 1),
    (r"^SSH-[\d.]+-dropbear_([\w.]+)", "ssh", "Dropbear", 1),
    (r"^SSH-[\d.]+-ROSSSH", "ssh", "MikroTik RouterOS SSH", None),
    (r"^SSH-[\d.]+-([\w.\-]+)", "ssh", None, 1),
    (r"^220.*vsFTPd ([\d.]+)", "ftp", "vsftpd", 1),
    (r"^220.*ProFTPD ([\d.]+\w*)", "ftp", "ProFTPD", 1),
    (r"^220.*Pure-FTPd", "ftp", "Pure-FTPd", None),
    (r"^220.*FileZilla Server ?([\d.]*)", "ftp", "FileZilla Server", 1),
    (r"^220.*Microsoft FTP Service", "ftp", "Microsoft IIS FTP", None),
    (r"^220.*MikroTik FTP server \(MikroTik ([\d.]+)", "ftp", "MikroTik RouterOS", 1),
    (r"^220.*FTP", "ftp", None, None),
    (r"^220.*E?SMTP.*Postfix", "smtp", "Postfix", None),
    (r"^220.*Exim ([\d.]+)", "smtp", "Exim", 1),
    (r"^220.*Microsoft ESMTP", "smtp", "Microsoft Exchange", None),
    (r"^220.*SMTP", "smtp", None, None),
    (r"^\+OK.*Dovecot", "pop3", "Dovecot", None),
    (r"^\+OK", "pop3", None, None),
    (r"^\* OK.*Dovecot", "imap", "Dovecot", None),
    (r"^\* OK", "imap", None, None),
    (r"^RFB (\d{3}\.\d{3})", "vnc", "VNC (RFB)", 1),
    (r"^AMQP", "amqp", "AMQP", None),
]


def _match_banner(banner: str) -> dict:
    for rx, svc, prod, grp in SIGS:
        m = re.search(rx, banner, re.I)
        if m:
            ver = m.group(grp) if grp and m.lastindex and m.lastindex >= grp else ""
            if prod is None and svc == "ssh" and grp:
                return {"service": svc, "product": m.group(grp), "version": ""}
            return {"service": svc, "product": prod or "", "version": ver}
    return {}


def _mysql(data: bytes) -> dict:
    # Paquete de saludo: 3 bytes longitud, 1 byte secuencia, 0x0a, versión\0
    if len(data) > 6 and data[4] == 0x0A:
        ver = data[5:data.find(b"\x00", 5)].decode("latin-1", "ignore")
        prod = "MariaDB" if "MariaDB" in ver else "MySQL"
        return {"service": "mysql", "product": prod, "version": ver.split("-")[0]}
    if len(data) > 6 and data[4] == 0xFF and b"not allowed to connect" in data:
        return {"service": "mysql", "product": "MySQL/MariaDB", "version": "",
                "note": "acceso restringido por IP"}
    return {}


HTTP_PRODUCTS = [
    (r"Apache/([\d.]+)", "Apache httpd"), (r"^Apache$", "Apache httpd"),
    (r"nginx/([\d.]+)", "nginx"), (r"^nginx$", "nginx"),
    (r"lighttpd/([\d.]+)", "lighttpd"), (r"Microsoft-IIS/([\d.]+)", "Microsoft IIS"),
    (r"Microsoft-HTTPAPI/([\d.]+)", "Microsoft HTTPAPI"), (r"GoAhead-Webs", "GoAhead"),
    (r"GoAhead-http", "GoAhead"), (r"Boa/([\d.\w]+)", "Boa"), (r"RomPager/([\d.]+)", "RomPager"),
    (r"mini_httpd/([\d.]+)", "mini_httpd"), (r"thttpd/([\d.]+)", "thttpd"),
    (r"Jetty\(([\d.\w\-]+)\)", "Jetty"), (r"openresty/([\d.]+)", "OpenResty"),
    (r"Caddy", "Caddy"), (r"cloudflare", "Cloudflare"), (r"uhttpd", "uhttpd (OpenWrt)"),
    (r"httpd/([\d.]+)\s*\(Synology", "Synology DSM"), (r"Werkzeug/([\d.]+)", "Werkzeug (Flask)"),
    (r"gunicorn/([\d.]+)", "gunicorn"), (r"Kestrel", "ASP.NET Kestrel"), (r"Tengine", "Tengine"),
    (r"Portable SDK for UPnP devices/([\d.]+)", "libupnp"), (r"MiniUPnPd/([\d.]+)", "MiniUPnPd"),
    (r"Virata-EmWeb/R([\d_]+)", "Virata EmWeb"), (r"HP HTTP Server", "HP HTTP Server"),
    (r"CUPS/([\d.]+)", "CUPS"), (r"Node\.js", "Node.js"), (r"Express", "Express"),
    (r"Python/([\d.]+)", "Python http.server"), (r"Mongoose/([\d.]+)", "Mongoose"),
]


def http_summary(r: dict) -> dict:
    h = r["headers"]
    body = r["body"][:200000].decode("utf-8", "replace")
    title = ""
    m = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
    if m:
        title = html.unescape(re.sub(r"\s+", " ", m.group(1))).strip()[:120]
    gen = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', body, re.I)
    server = h.get("server", "")
    prod, ver = "", ""
    for rx, name in HTTP_PRODUCTS:
        mm = re.search(rx, server, re.I)
        if mm:
            prod, ver = name, (mm.group(1).replace("_", ".") if mm.groups() else "")
            break
    ident = (title + " " + body[:4000]).lower()
    app = ""
    for key, name in (("routeros", "MikroTik RouterOS"), ("mikrotik", "MikroTik RouterOS"),
                      ("synology", "Synology DSM"), ("qnap", "QNAP"), ("openwrt", "OpenWrt LuCI"),
                      ("luci", "OpenWrt LuCI"), ("unifi", "Ubiquiti UniFi"), ("pfsense", "pfSense"),
                      ("opnsense", "OPNsense"), ("home assistant", "Home Assistant"),
                      ("proxmox", "Proxmox VE"), ("plex", "Plex"), ("jellyfin", "Jellyfin"),
                      ("hikvision", "Hikvision"), ("dahua", "Dahua"), ("tp-link", "TP-Link"),
                      ("fritz!box", "AVM FRITZ!Box"), ("wordpress", "WordPress"),
                      ("grafana", "Grafana"), ("portainer", "Portainer"), ("pi-hole", "Pi-hole"),
                      ("hp envy", "HP Embedded Web Server"), ("hp laserjet", "HP Embedded Web Server"),
                      ("epson", "Epson Web Config"), ("brother", "Brother Web"), ("zte", "ZTE"),
                      ("huawei", "Huawei"), ("sagemcom", "Sagemcom"), ("askey", "Askey"),
                      ("phpmyadmin", "phpMyAdmin"), ("jenkins", "Jenkins"), ("kibana", "Kibana"),
                      ("webmin", "Webmin"), ("cockpit", "Cockpit")):
        if key in ident:
            app = name
            break
    ros = re.search(r"RouterOS v?([\d.]+)", body)
    pw_form = bool(re.search(r"<input[^>]+type=[\"']?password", body, re.I))
    return {
        "status": r["status"], "server": server, "title": title, "app": app,
        "generator": gen.group(1) if gen else "", "powered_by": h.get("x-powered-by", ""),
        "location": h.get("location", ""), "auth": h.get("www-authenticate", ""),
        "headers": {k: v[:300] for k, v in h.items()}, "password_form": pw_form,
        "dir_listing": bool(re.search(r"<title>\s*Index of /|Directory listing for", body, re.I)),
        "routeros_version": ros.group(1) if ros else "",
        "product": prod, "version": ver, "body_len": len(r["body"]),
    }


async def _grab(ip, port, wait: float) -> bytes:
    async def go(conn: TCPConn):
        return await conn.recv(2048, timeout=wait)
    try:
        conn = await TCPConn.open(ip, port, timeout=3)
    except Exception:  # noqa: BLE001
        return b""
    try:
        return await go(conn)
    finally:
        await conn.close()


async def fingerprint(ip: str, port: int) -> dict:
    """Identifica el servicio de un puerto abierto y recoge toda la información útil."""
    svc = {"port": port, "proto": "tcp", "service": service_name(port), "product": "",
           "version": "", "banner": "", "tls": None, "http": None, "details": {}}
    # 1) Banner pasivo (protocolos que hablan primero)
    banner = b""
    if port not in HTTP_PORTS and port not in TLS_PORTS and port not in (22, 2222):
        banner = await _grab(ip, port, 2.5 if port in BANNER_PORTS else 1.5)
    if banner:
        text = banner.decode("latin-1", "ignore")
        svc["banner"] = re.sub(r"[^\x20-\x7e\r\n\t]", ".", text).strip()[:300]
        ident = _match_banner(text) or _mysql(banner)
        if banner[:1] == b"\xff" and len(banner) > 1 and banner[1] in (0xFB, 0xFC, 0xFD, 0xFE):
            ident = {"service": "telnet", "product": "Telnet", "version": ""}
        elif not ident and re.search(r"login:|username:|password:", text, re.I):
            ident = {"service": "telnet", "product": "Telnet", "version": ""}
        svc.update({k: v for k, v in ident.items() if k in ("service", "product", "version")})
    # 2) Sondas específicas según el puerto/servicio detectado
    s = svc["service"]
    if s == "ssh" or port in (22, 2222):
        info = await probes.ssh_info(ip, port)
        if info and info.get("banner", "").startswith("SSH-"):
            svc["details"]["ssh"] = info
            svc["service"] = "ssh"
            if not svc["product"]:
                svc.update(_match_banner(info["banner"]))
            svc["banner"] = info["banner"]
        return svc
    if s == "ftp" or port == 21:
        info = await probes.ftp_anonymous(ip, port)
        if info and info.get("banner", "").startswith("220"):
            svc["details"]["ftp"] = info
            svc["service"] = "ftp"
        return svc
    if s == "vnc" or port in (5900, 5901, 5902):
        info = await probes.vnc_info(ip, port)
        if info:
            svc["details"]["vnc"] = info
            svc.update({"service": "vnc", "product": "VNC", "version": info["version"]})
        return svc
    if s in ("telnet", "smtp", "pop3", "imap", "mysql") and banner:
        return svc
    special = {
        445: ("smb", probes.smb_info), 139: ("smb", probes.smb_info),
        3389: ("rdp", probes.rdp_info), 6379: ("redis", probes.redis_info),
        11211: ("memcached", probes.memcached_info), 1883: ("mqtt", probes.mqtt_info),
        5555: ("adb", probes.adb_info), 27017: ("mongodb", probes.mongodb_info),
        554: ("rtsp", probes.rtsp_info), 8554: ("rtsp", probes.rtsp_info),
        2375: ("docker", probes.docker_api), 2376: ("docker", probes.docker_api),
        9200: ("elasticsearch", probes.elastic_info),
    }
    if port in special:
        name, fn = special[port]
        info = await fn(ip, port)
        if info:
            svc["details"][name] = info
            svc["service"] = name
            if info.get("version"):
                svc["version"] = info["version"]
            if name in ("smb", "rdp", "redis", "memcached", "mqtt", "adb", "mongodb", "rtsp"):
                if name == "rtsp" and info.get("server"):
                    svc["product"] = info["server"]
                return svc
    # 3) TLS
    if port in TLS_PORTS or not banner:
        tls = await probes.tls_info(ip, port)
        if tls:
            svc["tls"] = tls
    # 4) HTTP (sobre TLS si lo hay)
    if port in HTTP_PORTS or not banner:
        r = await http_get(ip, port, "/", tls=bool(svc["tls"]), timeout=4)
        if r:
            hs = http_summary(r)
            svc["http"] = hs
            svc["service"] = "https" if svc["tls"] else "http"
            svc["product"] = hs["product"] or hs["app"] or svc["product"]
            svc["version"] = hs["version"] or svc["version"]
            if hs["routeros_version"]:
                svc["product"], svc["version"] = "MikroTik RouterOS", hs["routeros_version"]
            if not svc["banner"]:
                svc["banner"] = (hs["status_line"] if "status_line" in hs else
                                 f"HTTP {hs['status']} {hs['server']}").strip()
        elif svc["tls"] and svc["service"] in ("desconocido", "http"):
            svc["service"] = "tls"
    if not banner and not svc["http"] and not svc["tls"]:
        # Último intento: provocar respuesta con un salto de línea
        async def poke(conn: TCPConn):
            await conn.send(b"\r\n\r\n")
            return await conn.recv(1024, timeout=2)
        try:
            c = await TCPConn.open(ip, port, timeout=3)
            data = await poke(c)
            await c.close()
        except Exception:  # noqa: BLE001
            data = b""
        if data:
            t = data.decode("latin-1", "ignore")
            svc["banner"] = re.sub(r"[^\x20-\x7e\r\n\t]", ".", t).strip()[:300]
            r = parse_http(data)
            if r:
                svc["http"] = http_summary(r)
                svc["service"] = "http"
            else:
                svc.update({k: v for k, v in _match_banner(t).items()})
    return svc
