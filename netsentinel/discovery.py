"""Descubrimiento de dispositivos: ARP, ICMP, TCP, NetBIOS, mDNS, SSDP/UPnP, DNS inverso."""

import asyncio
import ipaddress
import json
import re
import socket
import struct
import time
import xml.etree.ElementTree as ET
from urllib.parse import urlparse

from . import dnsproto
from .netio import http_get, udp_collect, udp_request
from .util import C_ENV, run

PING_RE = re.compile(r"ttl=(\d+).*?time=([\d.]+)", re.I)


# ----------------------------------------------------------------- ARP ----
def neighbours() -> dict[str, dict]:
    """Tabla de vecinos del kernel (ARP) -> {ip: {mac, state, dev}}."""
    try:
        rows = json.loads(run(["ip", "-j", "-4", "neigh"]) or "[]")
    except json.JSONDecodeError:
        rows = []
    out = {}
    for r in rows:
        mac = r.get("lladdr")
        state = r.get("state") or []
        if mac and not set(state) & {"FAILED", "INCOMPLETE"}:
            out[r["dst"]] = {"mac": mac.lower(), "state": state, "dev": r.get("dev", "")}
    return out


async def arp_sweep(ips: list[str], rounds: int = 2) -> dict[str, dict]:
    """ARP sin privilegios: un datagrama UDP a cada IP obliga al kernel a resolver su MAC.

    Los dispositivos responden a ARP aunque tengan cortafuegos que bloquee ping/TCP,
    así que este método es el más fiable dentro de la red local.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setblocking(False)
    try:
        for _ in range(rounds):
            for i, ip in enumerate(ips):
                try:
                    sock.sendto(b"\x00", (ip, 9))
                except OSError:
                    pass
                if i % 64 == 63:
                    await asyncio.sleep(0.02)
            await asyncio.sleep(1.2)
    finally:
        sock.close()
    await asyncio.sleep(0.5)
    wanted = set(ips)
    return {ip: v for ip, v in neighbours().items() if ip in wanted}


# ---------------------------------------------------------------- ICMP ----
async def ping(ip: str, timeout: float = 1.0) -> dict | None:
    try:
        proc = await asyncio.create_subprocess_exec(
            "ping", "-c", "1", "-n", "-W", str(max(1, int(timeout))), ip,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL, env=C_ENV)
        out, _ = await asyncio.wait_for(proc.communicate(), timeout + 2)
    except (OSError, asyncio.TimeoutError, TimeoutError):
        return None
    m = PING_RE.search(out.decode(errors="ignore"))
    if proc.returncode == 0 and m:
        return {"ttl": int(m.group(1)), "rtt": float(m.group(2))}
    return None


async def tcp_alive(ip: str, ports=(80, 443, 22, 445, 139, 3389, 8080, 53, 62078, 5000),
                    timeout: float = 1.0) -> float | None:
    """Comprueba si responde algún puerto (abierto o RST). Devuelve RTT en ms."""
    async def one(p):
        t0 = time.monotonic()
        try:
            r, w = await asyncio.wait_for(asyncio.open_connection(ip, p), timeout)
            w.close()
            return (time.monotonic() - t0) * 1000
        except ConnectionRefusedError:
            return (time.monotonic() - t0) * 1000   # RST => el host existe
        except (OSError, asyncio.TimeoutError, TimeoutError):
            return None
    res = await asyncio.gather(*(one(p) for p in ports))
    vals = [r for r in res if r is not None]
    return min(vals) if vals else None


# --------------------------------------------------------- Nombres --------
async def reverse_dns(ip: str, timeout: float = 1.5) -> str:
    loop = asyncio.get_running_loop()
    try:
        name = await asyncio.wait_for(loop.run_in_executor(None, socket.gethostbyaddr, ip), timeout)
        return name[0]
    except (OSError, asyncio.TimeoutError, TimeoutError):
        return ""


def _nbns_status_query() -> bytes:
    tid = 0x4E53
    hdr = struct.pack(">HHHHHH", tid, 0x0000, 1, 0, 0, 0)
    # Nombre '*' codificado (first-level encoding) + NBSTAT (0x21) clase IN
    name = b"\x20" + b"CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" + b"\x00"
    return hdr + name + struct.pack(">HH", 0x21, 1)


async def netbios(ip: str) -> dict | None:
    data = await udp_request(ip, 137, _nbns_status_query(), timeout=1.0, retries=1)
    if not data or len(data) < 57:
        return None
    try:
        off = 12
        while data[off] != 0:
            off += data[off] + 1
        off += 1 + 4 + 4 + 2 + 2  # fin nombre, tipo/clase, ttl, rdlength
        count = data[off]
        off += 1
        names, group = [], ""
        for _ in range(count):
            nm = data[off:off + 15].decode("latin-1").strip()
            suffix = data[off + 15]
            flags = struct.unpack(">H", data[off + 16:off + 18])[0]
            off += 18
            is_group = bool(flags & 0x8000)
            if suffix == 0x00 and not is_group and nm not in names:
                names.insert(0, nm)
            elif suffix == 0x00 and is_group:
                group = nm
            elif suffix == 0x20 and nm not in names:
                names.append(nm)
        mac = ":".join(f"{b:02x}" for b in data[off:off + 6])
        return {"name": names[0] if names else "", "workgroup": group,
                "mac": mac if mac != "00:00:00:00:00:00" else ""}
    except (IndexError, struct.error):
        return None


async def mdns_reverse(ip: str) -> str:
    q = dnsproto.build_query(dnsproto.reverse_name(ip), dnsproto.T_PTR, rd=False,
                             unicast_response=True)
    data = await udp_request(ip, 5353, q, timeout=1.0, retries=1)
    if not data:
        return ""
    try:
        for r in dnsproto.parse(data)["records"]:
            if r["type"] == dnsproto.T_PTR and isinstance(r["value"], str):
                return r["value"].rstrip(".")
    except (ValueError, struct.error, IndexError):
        pass
    return ""


MDNS_SERVICES = [
    "_http._tcp.local", "_https._tcp.local", "_ipp._tcp.local", "_ipps._tcp.local",
    "_printer._tcp.local", "_pdl-datastream._tcp.local", "_scanner._tcp.local",
    "_uscan._tcp.local", "_airplay._tcp.local", "_raop._tcp.local",
    "_googlecast._tcp.local", "_spotify-connect._tcp.local", "_smb._tcp.local",
    "_afpovertcp._tcp.local", "_ssh._tcp.local", "_sftp-ssh._tcp.local",
    "_workstation._tcp.local", "_device-info._tcp.local", "_hap._tcp.local",
    "_homekit._tcp.local", "_companion-link._tcp.local", "_sonos._tcp.local",
    "_amzn-wplay._tcp.local", "_androidtvremote2._tcp.local", "_matter._tcp.local",
    "_home-assistant._tcp.local", "_esphomelib._tcp.local", "_mqtt._tcp.local",
    "_rfb._tcp.local", "_adb-tls-connect._tcp.local", "_daap._tcp.local",
    "_apple-mobdev2._tcp.local", "_sleep-proxy._udp.local", "_nvstream._tcp.local",
    "_hue._tcp.local", "_meshcop._udp.local", "_ftp._tcp.local", "_nfs._tcp.local",
]


def _mdns_multi_query(names: list[str]) -> bytes:
    hdr = struct.pack(">HHHHHH", 0, 0, len(names), 0, 0, 0)
    body = b"".join(dnsproto.encode_name(n) + struct.pack(">HH", dnsproto.T_PTR, 0x8001)
                    for n in names)
    return hdr + body


async def mdns_browse(duration: float = 3.0) -> dict[str, dict]:
    """Descubre servicios Bonjour/Avahi. Devuelve {ip: {name, services[], txt{}}}."""
    payloads = []
    for i in range(0, len(MDNS_SERVICES), 12):
        payloads.append(_mdns_multi_query(MDNS_SERVICES[i:i + 12]))
    results = await asyncio.gather(*(udp_collect(("224.0.0.251", 5353), p, duration=duration)
                                     for p in payloads))
    hosts: dict[str, dict] = {}
    srv_target: dict[str, tuple[str, int]] = {}  # instancia -> (target, puerto)
    target_ip: dict[str, str] = {}
    inst_txt: dict[str, list[str]] = {}
    inst_type: dict[str, str] = {}
    src_inst: dict[str, set] = {}
    for batch in results:
        for data, src in batch:
            try:
                recs = dnsproto.parse(data)["records"]
            except (ValueError, struct.error, IndexError):
                continue
            for r in recs:
                v = r["value"]
                if r["type"] == dnsproto.T_PTR and isinstance(v, str) and r["name"] in MDNS_SERVICES:
                    inst_type[v] = r["name"]
                    src_inst.setdefault(src, set()).add(v)
                elif r["type"] == dnsproto.T_SRV and isinstance(v, dict):
                    srv_target[r["name"]] = (v["target"], v["port"])
                    src_inst.setdefault(src, set()).add(r["name"])
                elif r["type"] == dnsproto.T_A and isinstance(v, str):
                    target_ip[r["name"]] = v
                elif r["type"] == dnsproto.T_TXT and isinstance(v, list):
                    inst_txt[r["name"]] = v
    for src, insts in src_inst.items():
        for inst in insts:
            ip = src
            tgt = srv_target.get(inst)
            if tgt and tgt[0] in target_ip:
                ip = target_ip[tgt[0]]
            h = hosts.setdefault(ip, {"name": "", "services": [], "txt": {}, "hostname": ""})
            stype = inst_type.get(inst) or ".".join(inst.split(".")[-3:])
            label = stype.replace(".local", "").replace("._tcp", "").replace("._udp", "").lstrip("_")
            friendly = inst.split("._")[0].replace("\\032", " ").replace("\\", "")
            entry = {"type": label, "instance": friendly, "port": tgt[1] if tgt else None}
            if entry not in h["services"]:
                h["services"].append(entry)
            if tgt:
                h["hostname"] = tgt[0].rstrip(".")
            for kv in inst_txt.get(inst, []):
                if "=" in kv:
                    k, val = kv.split("=", 1)
                    if k in ("fn", "md", "model", "ty", "usb_MDL", "usb_MFG", "manufacturer",
                             "am", "osxvers", "rpMd", "name", "product", "mf", "deviceid"):
                        h["txt"][k] = val[:80]
            if not h["name"] and friendly and label not in ("sleep-proxy", "device-info"):
                h["name"] = h["txt"].get("fn") or friendly
    return hosts


# ------------------------------------------------------------- SSDP -------
SSDP_MSEARCH = (b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"
                b"MAN: \"ssdp:discover\"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n")


async def ssdp_discover(duration: float = 3.0) -> dict[str, dict]:
    res = await udp_collect(("239.255.255.250", 1900), SSDP_MSEARCH, duration=duration, resend=1)
    hosts: dict[str, dict] = {}
    for data, src in res:
        txt = data.decode("latin-1", "ignore")
        hdr = {}
        for ln in txt.split("\r\n")[1:]:
            if ":" in ln:
                k, v = ln.split(":", 1)
                hdr[k.strip().lower()] = v.strip()
        h = hosts.setdefault(src, {"server": "", "locations": [], "types": [], "igd": False})
        if hdr.get("server"):
            h["server"] = hdr["server"]
        loc = hdr.get("location")
        if loc and loc not in h["locations"]:
            h["locations"].append(loc)
        st = hdr.get("st", "")
        if st and st not in h["types"]:
            h["types"].append(st)
        if "InternetGatewayDevice" in st or "WANIPConnection" in st or "WANPPPConnection" in st:
            h["igd"] = True
    # Descarga la descripción XML del dispositivo (nombre, fabricante, modelo)
    async def describe(ip, h):
        for loc in h["locations"][:2]:
            try:
                u = urlparse(loc)
                if u.hostname != ip:
                    continue
                r = await http_get(ip, u.port or 80, u.path or "/", tls=u.scheme == "https",
                                   timeout=3, host=u.netloc)
                if not r or r["status"] != 200:
                    continue
                info = _parse_upnp_xml(r["body"])
                if info:
                    h.update(info)
                    return
            except Exception:  # noqa: BLE001
                continue
    await asyncio.gather(*(describe(ip, h) for ip, h in hosts.items()))
    return hosts


def _parse_upnp_xml(body: bytes) -> dict:
    try:
        root = ET.fromstring(body.strip())
    except ET.ParseError:
        return {}
    for el in root.iter():
        if isinstance(el.tag, str) and "}" in el.tag:
            el.tag = el.tag.split("}", 1)[1]
    dev = root.find(".//device")
    if dev is None:
        return {}
    def g(tag):
        e = dev.find(tag)
        return (e.text or "").strip() if e is not None and e.text else ""
    out = {"friendly_name": g("friendlyName"), "manufacturer": g("manufacturer"),
           "model": g("modelName"), "model_number": g("modelNumber"),
           "device_type": g("deviceType"), "serial": g("serialNumber")}
    services = [s.text for s in root.iter("serviceType") if s.text]
    if any("WANIPConnection" in s or "WANPPPConnection" in s for s in services):
        out["igd"] = True
    out["upnp_services"] = sorted({s.split(":")[-2] for s in services if s.count(":") >= 2})[:20]
    return {k: v for k, v in out.items() if v}


def same_subnet(ip: str, network: str | None) -> bool:
    if not network:
        return False
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(network, strict=False)
    except ValueError:
        return False
