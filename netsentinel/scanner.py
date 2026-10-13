"""Orquestador del escaneo: descubrimiento -> puertos -> servicios -> análisis."""

import asyncio
import ipaddress
import threading
import time
import traceback

from . import classify, discovery, netinfo, oui, probes, services, vulns
from .config import MAX_TARGET_HOSTS
from .ports import PROFILES, parse_ports
from .util import expand_target, raise_nofile

PHASES = [
    ("prep", "Preparando", 0, 3),
    ("discovery", "Descubriendo dispositivos", 3, 25),
    ("names", "Identificando nombres y fabricantes", 25, 32),
    ("ports", "Escaneando puertos", 32, 72),
    ("services", "Detectando servicios y versiones", 72, 92),
    ("analysis", "Analizando vulnerabilidades", 92, 100),
]


class ScanJob:
    def __init__(self, target: str, profile: str = "estandar", custom_ports: str = "",
                 storage=None):
        self.target = target.strip()
        self.profile = profile if profile in PROFILES else "estandar"
        self.custom_ports = custom_ports
        self.storage = storage
        self.cancel = threading.Event()
        self.lock = threading.Lock()
        self.state = {
            "running": False, "phase": "prep", "phase_label": "En cola", "percent": 0.0,
            "message": "", "started": None, "finished": None, "error": None,
            "hosts_found": 0, "open_ports": 0, "log": [], "scan_id": None,
        }
        self.hosts: dict[str, dict] = {}
        self.result: dict | None = None
        self._ports_total = 1
        self._ports_done = 0

    # ---------------------------------------------------------- estado ---
    def log(self, msg: str):
        with self.lock:
            self.state["log"].append({"t": time.time(), "msg": msg})
            self.state["log"] = self.state["log"][-200:]
            self.state["message"] = msg

    def set_phase(self, key: str, frac: float = 0.0):
        for k, label, a, b in PHASES:
            if k == key:
                with self.lock:
                    self.state["phase"] = k
                    self.state["phase_label"] = label
                    self.state["percent"] = round(a + (b - a) * max(0.0, min(1.0, frac)), 1)

    def snapshot(self) -> dict:
        with self.lock:
            s = dict(self.state)
            s["log"] = list(self.state["log"][-40:])
            s["hosts"] = [_brief(h) for h in sorted(self.hosts.values(), key=_ipkey)]
            return s

    # ------------------------------------------------------------ run ----
    def start(self):
        th = threading.Thread(target=self._run_thread, daemon=True, name="scan")
        th.start()
        return th

    def _run_thread(self):
        with self.lock:
            self.state["running"] = True
            self.state["started"] = time.time()
        try:
            self.result = asyncio.run(self._run())
            if self.storage and self.result and not self.cancel.is_set():
                sid = self.storage.save_scan(self.result)
                self.result["id"] = sid
                with self.lock:
                    self.state["scan_id"] = sid
            self.set_phase("analysis", 1.0)
            self.log("Escaneo cancelado" if self.cancel.is_set() else "Escaneo completado")
        except Exception as e:  # noqa: BLE001
            traceback.print_exc()
            with self.lock:
                self.state["error"] = str(e)
            self.log(f"Error: {e}")
        finally:
            with self.lock:
                self.state["running"] = False
                self.state["finished"] = time.time()

    async def _run(self) -> dict:
        t0 = time.time()
        self.set_phase("prep")
        ips = expand_target(self.target, MAX_TARGET_HOSTS)
        net = netinfo.snapshot()
        gw = net.get("gateway")
        primary = net.get("primary") or {}
        self_ip = primary.get("ip")
        local_net = primary.get("network")
        prof = PROFILES[self.profile]
        ports = parse_ports(self.custom_ports) if self.custom_ports else prof["ports"]
        nofile = raise_nofile()
        conc = max(64, min(1000, nofile - 200))
        self.log(f"Objetivo {self.target}: {len(ips)} direcciones · perfil {prof['label']} · "
                 f"{len(ports)} puertos · concurrencia {conc}")

        # ------------------------------------------------ Descubrimiento
        self.set_phase("discovery")
        local_ips = [ip for ip in ips if discovery.same_subnet(ip, local_net) and ip != self_ip]
        remote_ips = [ip for ip in ips if ip not in set(local_ips) and ip != self_ip]
        self.log(f"Barrido ARP de {len(local_ips)} direcciones locales + ICMP/TCP")
        ping_sem = asyncio.Semaphore(128)
        pinged: dict[str, dict] = {}
        done = 0

        async def do_ping(ip):
            nonlocal done
            async with ping_sem:
                if self.cancel.is_set():
                    return
                r = await discovery.ping(ip)
                if r:
                    pinged[ip] = r
                done += 1
                self.set_phase("discovery", 0.8 * done / max(1, len(ips)))

        arp_task = asyncio.create_task(discovery.arp_sweep(local_ips)) if local_ips else None
        mdns_task = asyncio.create_task(discovery.mdns_browse(3.0)) if local_net else None
        ssdp_task = asyncio.create_task(discovery.ssdp_discover(3.0)) if local_net else None
        await asyncio.gather(*(do_ping(ip) for ip in ips if ip != self_ip))
        arp = await arp_task if arp_task else {}
        mdns = await mdns_task if mdns_task else {}
        ssdp = await ssdp_task if ssdp_task else {}
        tcp_found: dict[str, float] = {}
        if remote_ips and not self.cancel.is_set():
            missing = [ip for ip in remote_ips if ip not in pinged]
            self.log(f"Sondeo TCP de {len(missing)} direcciones que no responden a ping")
            tsem = asyncio.Semaphore(max(8, conc // 10))

            async def do_tcp(ip):
                async with tsem:
                    if self.cancel.is_set():
                        return
                    r = await discovery.tcp_alive(ip)
                    if r is not None:
                        tcp_found[ip] = r
            await asyncio.gather(*(do_tcp(ip) for ip in missing))
        wanted = set(ips)
        neigh = {ip: v for ip, v in discovery.neighbours().items() if ip in wanted}
        alive = set(arp) | set(pinged) | set(tcp_found) | (set(mdns) & wanted) | (set(ssdp) & wanted)
        alive |= set(neigh) & set(local_ips)
        if self_ip in wanted:
            alive.add(self_ip)
        for ip in alive:
            src = []
            if ip in arp:
                src.append("ARP")
            if ip in pinged:
                src.append("ICMP")
            if ip in tcp_found:
                src.append("TCP")
            if ip in mdns:
                src.append("mDNS")
            if ip in ssdp:
                src.append("SSDP")
            mac = (arp.get(ip) or neigh.get(ip) or {}).get("mac", "")
            if ip == self_ip:
                mac, src = primary.get("mac", ""), ["Local"]
            pg = pinged.get(ip, {})
            self.hosts[ip] = {
                "ip": ip, "mac": mac, "vendor": "", "random_mac": oui.is_random(mac) if mac else False,
                "hostname": "", "names": {}, "ttl": pg.get("ttl"),
                "rtt": pg.get("rtt") or (round(tcp_found[ip], 1) if ip in tcp_found else None),
                "sources": src, "services": [], "udp": {}, "upnp": ssdp.get(ip),
                "mdns": mdns.get(ip, {}), "netbios": None, "is_gateway": ip == gw,
                "is_self": ip == self_ip, "local": ip in local_ips or ip == self_ip,
            }
        with self.lock:
            self.state["hosts_found"] = len(self.hosts)
        self.log(f"{len(self.hosts)} dispositivos activos encontrados")
        self.set_phase("discovery", 1)

        # ------------------------------------------------ Nombres
        self.set_phase("names")
        nsem = asyncio.Semaphore(48)
        ndone = 0

        async def names(h):
            nonlocal ndone
            async with nsem:
                if self.cancel.is_set():
                    return
                rd, nb, md = await asyncio.gather(discovery.reverse_dns(h["ip"]),
                                                  discovery.netbios(h["ip"]),
                                                  discovery.mdns_reverse(h["ip"]))
                if rd and rd != "_gateway":
                    h["names"]["dns"] = rd
                if nb:
                    h["netbios"] = nb
                    if nb.get("name"):
                        h["names"]["netbios"] = nb["name"]
                    if not h["mac"] and nb.get("mac"):
                        h["mac"] = nb["mac"]
                if md:
                    h["names"]["mdns"] = md
                if h["mdns"].get("name"):
                    h["names"]["bonjour"] = h["mdns"]["name"]
                if h["mdns"].get("hostname"):
                    h["names"].setdefault("mdns", h["mdns"]["hostname"])
                if h.get("upnp") and h["upnp"].get("friendly_name"):
                    h["names"]["upnp"] = h["upnp"]["friendly_name"]
                if h["is_self"]:
                    h["names"]["local"] = net.get("hostname", "")
                h["vendor"] = oui.lookup(h["mac"]) if h["mac"] else ""
                if not h["vendor"] and h.get("upnp", {}) and (h["upnp"] or {}).get("manufacturer"):
                    h["vendor"] = h["upnp"]["manufacturer"]
                h["hostname"] = (h["names"].get("local") or h["names"].get("bonjour") or
                                 h["names"].get("upnp") or h["names"].get("netbios") or
                                 h["names"].get("mdns") or h["names"].get("dns") or "")
                ndone += 1
                self.set_phase("names", ndone / max(1, len(self.hosts)))
        await asyncio.gather(*(names(h) for h in self.hosts.values()))

        # ------------------------------------------------ Puertos
        self.set_phase("ports")
        psem = asyncio.Semaphore(conc)
        self._ports_total = max(1, len(ports) * len(self.hosts))
        self._ports_done = 0

        def prog(n):
            self._ports_done += n
            if self._ports_done % 200 == 0:
                self.set_phase("ports", self._ports_done / self._ports_total)

        async def scan_host(h):
            timeout = 0.9 if h["local"] else 1.5
            if h["rtt"]:
                timeout = max(timeout, min(3.0, h["rtt"] / 1000 * 6))
            opened = await services.scan_ports(h["ip"], ports, psem, timeout, prog, self.cancel)
            h["services"] = [{"port": o["port"], "proto": "tcp", "service": "", "rtt": o["rtt"]}
                             for o in opened]
            with self.lock:
                self.state["open_ports"] += len(opened)
            if opened:
                self.log(f"{h['ip']}: {len(opened)} puertos abiertos "
                         f"({', '.join(str(o['port']) for o in opened[:12])}{'…' if len(opened) > 12 else ''})")
        if ports:
            self.log(f"Escaneando {len(ports)} puertos TCP en {len(self.hosts)} dispositivos")
            await asyncio.gather(*(scan_host(h) for h in self.hosts.values()))
        self.set_phase("ports", 1)

        # ------------------------------------------------ Servicios
        self.set_phase("services")
        deep = prof["deep"]
        tasks_total = sum(len(h["services"]) for h in self.hosts.values()) + len(self.hosts)
        tdone = 0
        fsem = asyncio.Semaphore(40)

        async def fp(h, s):
            nonlocal tdone
            async with fsem:
                if self.cancel.is_set():
                    return
                try:
                    info = await asyncio.wait_for(services.fingerprint(h["ip"], s["port"]), 40)
                    rtt = s.get("rtt")
                    s.clear()
                    s.update(info)
                    s["rtt"] = rtt
                    if deep and s.get("http") and s["http"].get("status"):
                        extra = await asyncio.wait_for(
                            vulns.http_extra(h["ip"], s["port"], bool(s.get("tls"))), 30)
                        h.setdefault("extra_findings", []).extend(extra)
                except (asyncio.TimeoutError, TimeoutError):
                    s.setdefault("service", "desconocido")
                except Exception as e:  # noqa: BLE001
                    s.setdefault("service", "desconocido")
                    s["error"] = str(e)
                tdone += 1
                self.set_phase("services", tdone / max(1, tasks_total))

        async def udp(h):
            nonlocal tdone
            async with fsem:
                if self.cancel.is_set() or h["is_self"]:
                    tdone += 1
                    return
                snmp, dns, ntp, tftp = await asyncio.gather(
                    probes.snmp_info(h["ip"]), probes.dns_info(h["ip"]),
                    probes.ntp_info(h["ip"]), probes.tftp_info(h["ip"]))
                h["udp"] = {k: v for k, v in (("snmp", snmp), ("dns", dns), ("ntp", ntp),
                                              ("tftp", tftp)) if v}
                tdone += 1
                self.set_phase("services", tdone / max(1, tasks_total))
        if deep or ports:
            await asyncio.gather(*(fp(h, s) for h in self.hosts.values() for s in h["services"]),
                                 *(udp(h) for h in self.hosts.values()))

        # ------------------------------------------------ Análisis
        self.set_phase("analysis")
        prev = self.storage.known_devices() if self.storage else {}
        for h in self.hosts.values():
            h["type"], h["type_reason"] = classify.classify(h, gw, self_ip)
            h["os"] = classify.guess_os(h)
            h["findings"] = vulns.evaluate(h)
            h["risk"] = vulns.host_risk(h["findings"])
            key = h["mac"] or h["ip"]
            known = prev.get(key)
            h["new"] = bool(prev) and known is None
            if known:
                h["alias"] = known.get("alias") or ""
                h["trusted"] = bool(known.get("trusted"))
                h["first_seen"] = known.get("first_seen")
        net_findings = vulns.wifi_findings(net.get("wifi"))
        hosts = sorted(self.hosts.values(), key=_ipkey)
        score = vulns.network_score(hosts, net_findings)
        result = {
            "version": 1, "target": self.target, "profile": self.profile,
            "profile_label": prof["label"], "ports_scanned": len(ports),
            "started": t0, "finished": time.time(), "duration": round(time.time() - t0, 1),
            "network": net, "hosts": hosts, "network_findings": net_findings,
            "score": score, "cancelled": self.cancel.is_set(),
        }
        result["summary"] = summarize(result)
        return result


def _ipkey(h):
    try:
        return int(ipaddress.ip_address(h["ip"]))
    except ValueError:
        return 0


def _brief(h: dict) -> dict:
    return {"ip": h["ip"], "mac": h.get("mac", ""), "vendor": h.get("vendor", ""),
            "hostname": h.get("hostname", ""), "ports": [s["port"] for s in h.get("services", [])],
            "is_gateway": h.get("is_gateway"), "is_self": h.get("is_self")}


def summarize(r: dict) -> dict:
    hosts = r["hosts"]
    types, vendors, svc_count, port_count = {}, {}, {}, {}
    for h in hosts:
        types[h.get("type", "unknown")] = types.get(h.get("type", "unknown"), 0) + 1
        v = h.get("vendor") or "Desconocido"
        vendors[v] = vendors.get(v, 0) + 1
        for s in h.get("services", []):
            name = s.get("service") or "desconocido"
            svc_count[name] = svc_count.get(name, 0) + 1
            port_count[s["port"]] = port_count.get(s["port"], 0) + 1
    return {
        "hosts": len(hosts), "open_ports": sum(len(h.get("services", [])) for h in hosts),
        "findings": r["score"]["counts"], "score": r["score"]["score"], "grade": r["score"]["grade"],
        "new_devices": sum(1 for h in hosts if h.get("new")),
        "types": types, "vendors": vendors, "services": svc_count, "ports": port_count,
    }
