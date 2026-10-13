"""Información de la red local: interfaces, puerta de enlace, DNS y Wi-Fi."""

import ipaddress
import json
import socket

from .util import run


def interfaces() -> list[dict]:
    try:
        data = json.loads(run(["ip", "-j", "addr"]) or "[]")
    except json.JSONDecodeError:
        data = []
    out = []
    for itf in data:
        name = itf.get("ifname", "")
        if name == "lo":
            continue
        for a in itf.get("addr_info", []):
            if a.get("family") != "inet":
                continue
            net = ipaddress.ip_interface(f"{a['local']}/{a['prefixlen']}").network
            out.append({
                "name": name,
                "ip": a["local"],
                "prefix": a["prefixlen"],
                "network": str(net),
                "mac": itf.get("address", ""),
                "up": itf.get("operstate") in ("UP", "UNKNOWN") and "UP" in itf.get("flags", []),
                "kind": _iface_kind(name),
            })
    return out


def _iface_kind(name: str) -> str:
    if name.startswith(("wl", "wlan")):
        return "wifi"
    if name.startswith(("en", "eth")):
        return "ethernet"
    if name.startswith(("docker", "br-", "veth", "virbr", "vbox", "vmnet")):
        return "virtual"
    if name.startswith(("tun", "tap", "wg", "ppp")):
        return "vpn"
    return "otro"


def default_route() -> dict:
    try:
        routes = json.loads(run(["ip", "-j", "route", "show", "default"]) or "[]")
    except json.JSONDecodeError:
        routes = []
    routes.sort(key=lambda r: r.get("metric", 0))
    for r in routes:
        if r.get("gateway"):
            return {"gateway": r["gateway"], "dev": r.get("dev", ""), "src": r.get("prefsrc", "")}
    return {}


def dns_servers() -> list[str]:
    servers = []
    try:
        with open("/etc/resolv.conf", encoding="utf-8") as fh:
            for line in fh:
                parts = line.split()
                if len(parts) >= 2 and parts[0] == "nameserver":
                    servers.append(parts[1])
    except OSError:
        pass
    # systemd-resolved: el resolv.conf apunta a 127.0.0.53, mostramos los reales
    if servers == ["127.0.0.53"]:
        txt = run(["resolvectl", "dns"])
        for line in txt.splitlines():
            if ":" in line:
                servers.extend(x for x in line.split(":", 1)[1].split() if x)
    return servers


def wifi_info() -> dict | None:
    txt = run(["nmcli", "-t", "-f", "IN-USE,SSID,BSSID,SECURITY,SIGNAL,CHAN,FREQ,RATE",
               "dev", "wifi", "list", "--rescan", "no"])
    for line in txt.splitlines():
        # nmcli -t escapa ':' como '\:' (en el BSSID)
        parts = _split_nmcli(line)
        if len(parts) >= 8 and parts[0].strip() == "*":
            return {
                "ssid": parts[1], "bssid": parts[2], "security": parts[3] or "Abierta",
                "signal": _int(parts[4]), "channel": _int(parts[5]),
                "freq": parts[6], "rate": parts[7],
            }
    return None


def _split_nmcli(line: str) -> list[str]:
    out, cur, esc = [], "", False
    for ch in line:
        if esc:
            cur += ch
            esc = False
        elif ch == "\\":
            esc = True
        elif ch == ":":
            out.append(cur)
            cur = ""
        else:
            cur += ch
    out.append(cur)
    return out


def _int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def snapshot() -> dict:
    itfs = interfaces()
    route = default_route()
    primary = None
    for i in itfs:
        if i["name"] == route.get("dev"):
            primary = i
            break
    if primary is None:
        primary = next((i for i in itfs if i["kind"] in ("wifi", "ethernet") and i["up"]), None)
    return {
        "hostname": socket.gethostname(),
        "interfaces": itfs,
        "gateway": route.get("gateway"),
        "gateway_dev": route.get("dev"),
        "primary": primary,
        "suggested_target": primary["network"] if primary else "192.168.1.0/24",
        "dns": dns_servers(),
        "wifi": wifi_info() if primary and primary["kind"] == "wifi" else None,
    }
