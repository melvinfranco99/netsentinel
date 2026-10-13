"""Motor de reglas: convierte los datos recogidos de cada host en hallazgos con solución."""

import asyncio
import random
import re
import string
import time

from . import cvedb, knowledge
from .netio import http_get

SEC_HEADERS = {
    "x-frame-options": "X-Frame-Options",
    "x-content-type-options": "X-Content-Type-Options",
    "content-security-policy": "Content-Security-Policy",
}
DB_PORTS = {3306: "MySQL/MariaDB", 5432: "PostgreSQL", 1433: "SQL Server", 1521: "Oracle",
            5984: "CouchDB", 9042: "Cassandra", 7474: "Neo4j", 8086: "InfluxDB"}
K8S_PORTS = {6443: "API de Kubernetes", 10250: "Kubelet", 2379: "etcd", 2380: "etcd (peer)"}
SENSITIVE_PATHS = [
    ("/.git/HEAD", rb"^ref: refs/"), ("/.env", rb"(?m)^[A-Z_]+=.+"),
    ("/server-status", rb"Apache Server Status"), ("/phpinfo.php", rb"phpinfo\(\)|PHP Version"),
    ("/.DS_Store", rb"^\x00\x00\x00\x01Bud1"), ("/backup.zip", rb"^PK\x03\x04"),
    ("/config.json", rb"(?i)\"(password|secret|api_?key)\""),
]


def make(fid: str, port=None, service="", evidence="", **fmt) -> dict:
    k = knowledge.get(fid)

    def f(s):
        try:
            return s.format(**fmt)
        except (KeyError, IndexError):
            return s
    return {
        "fid": fid, "title": f(k["title"]), "severity": fmt.pop("severity", None) or k["severity"],
        "category": k["category"], "description": f(k["description"]), "impact": f(k["impact"]),
        "fix": [f(x) for x in k["fix"]], "refs": list(k["refs"]), "port": port,
        "service": service, "evidence": str(evidence)[:400],
    }


def cve_finding(hit: dict, port, service) -> dict:
    title = hit["title"]
    return {
        "fid": "cve:" + (hit["cves"][0] if hit["cves"] else f"{hit['product']}-{hit['version']}"),
        "title": f"{hit['product']} {hit['version']}: {title}".strip(),
        "severity": hit["severity"], "category": "Software vulnerable",
        "description": f"La versión detectada ({hit['product']} {hit['version']}) está afectada"
                       + (f" por {', '.join(hit['cves'])}." if hit["cves"] else ". " + title + "."),
        "impact": title, "fix": [hit["fix"]],
        "refs": hit["cves"] + [f"https://nvd.nist.gov/vuln/detail/{c}" for c in hit["cves"][:1]],
        "port": port, "service": service, "evidence": f"{hit['product']} {hit['version']}",
    }


async def http_extra(ip: str, port: int, tls: bool) -> list[dict]:
    """Busca ficheros sensibles expuestos comparando con una respuesta 404 de referencia."""
    rnd = "/" + "".join(random.choices(string.ascii_lowercase, k=12)) + ".txt"
    base = await http_get(ip, port, rnd, tls=tls, timeout=4, limit=4096)
    soft404 = base is not None and base["status"] == 200
    out = []

    async def probe(path, rx):
        r = await http_get(ip, port, path, tls=tls, timeout=4, limit=65536)
        if not r or r["status"] != 200 or not r["body"]:
            return
        if soft404 and abs(len(r["body"]) - len(base["body"])) < 50:
            return
        if re.search(rx, r["body"][:65536]):
            out.append(make("sensitive_file", port, "https" if tls else "http",
                            evidence=f"GET {path} -> 200 ({len(r['body'])} bytes)", path=path))
    await asyncio.gather(*(probe(p, rx) for p, rx in SENSITIVE_PATHS))
    return out


def evaluate(host: dict) -> list[dict]:
    F: list[dict] = []
    seen_cves = set()

    def add_cves(product, version, port, service):
        for hit in cvedb.match(product, version):
            key = (hit["title"], port)
            if key not in seen_cves:
                seen_cves.add(key)
                F.append(cve_finding(hit, port, service))

    ports = {s["port"]: s for s in host.get("services", [])}
    for p, s in ports.items():
        svc = s.get("service", "")
        d = s.get("details", {})
        prod, ver = s.get("product", ""), s.get("version", "")
        if p in (23, 2323) or svc == "telnet":
            F.append(make("telnet_open", p, "telnet", s.get("banner", "")))
        if p in (512, 513, 514):
            F.append(make("rservices_open", p, svc))
        if svc == "ftp":
            ftp = d.get("ftp", {})
            if ftp.get("anonymous"):
                F.append(make("ftp_anonymous", p, "ftp", "USER anonymous -> 230 Login successful"))
            if not ftp.get("tls"):
                F.append(make("ftp_cleartext", p, "ftp", s.get("banner", "")))
        if svc == "ssh" and "ssh" in d:
            ssh = d["ssh"]
            if ssh.get("banner", "").startswith("SSH-1."):
                F.append(make("ssh_v1", p, "ssh", ssh["banner"]))
            weak = ssh.get("weak", {})
            if "none" in weak.get("cipher", []):
                F.append(make("ssh_none_cipher", p, "ssh", "cipher: none"))
            algos = sorted({a for v in weak.values() for a in v if a != "none"})
            if algos:
                F.append(make("ssh_weak_algos", p, "ssh", ", ".join(algos),
                              algos=", ".join(algos[:8]) + ("…" if len(algos) > 8 else "")))
            if ssh.get("terrapin"):
                F.append(make("ssh_terrapin", p, "ssh", "chacha20-poly1305/etm sin kex-strict"))
        if svc == "smb" and "smb" in d:
            smb = d["smb"]
            if smb.get("smb1"):
                F.append(make("smb1_enabled", p, "smb", "Negociación SMB1 'NT LM 0.12' aceptada"))
            if smb.get("smb2") and not smb.get("signing_required"):
                F.append(make("smb_signing", p, "smb", f"Dialecto {smb.get('dialect')}, firma no requerida"))
        if p in (139, 445) and not any(f["fid"] == "smb_exposed" for f in F):
            F.append(make("smb_exposed", p, svc))
        if svc == "rdp" or p == 3389:
            rdp = d.get("rdp", {})
            if rdp.get("nla_required") is False:
                F.append(make("rdp_no_nla", p, "rdp", "El servidor aceptó seguridad RDP estándar"))
            else:
                F.append(make("rdp_exposed", p, "rdp"))
        if svc == "vnc" and "vnc" in d:
            if d["vnc"].get("no_auth"):
                F.append(make("vnc_no_auth", p, "vnc", f"{d['vnc']['version']} security types {d['vnc']['types']}"))
            else:
                F.append(make("vnc_exposed", p, "vnc", d["vnc"]["version"]))
        if "redis" in d:
            if d["redis"].get("auth") is False:
                F.append(make("redis_noauth", p, "redis", "INFO server respondido sin AUTH"))
            if d["redis"].get("version"):
                add_cves("Redis", d["redis"]["version"], p, "redis")
        if "memcached" in d:
            F.append(make("memcached_open", p, "memcached", f"stats -> version {d['memcached'].get('version')}"))
            add_cves("Memcached", d["memcached"].get("version", ""), p, "memcached")
        if "mongodb" in d:
            F.append(make("mongodb_open", p, "mongodb", "isMaster respondido"))
        if "elasticsearch" in d and d["elasticsearch"].get("open"):
            F.append(make("elastic_open", p, "elasticsearch", f"versión {d['elasticsearch'].get('version')}"))
            add_cves("Elasticsearch", d["elasticsearch"].get("version", ""), p, "elasticsearch")
        if "docker" in d:
            F.append(make("docker_api", p, "docker", f"GET /version -> Docker {d['docker'].get('version')}"))
        if "adb" in d:
            if d["adb"].get("auth") is False:
                F.append(make("adb_open", p, "adb", d["adb"].get("banner", "CNXN")))
            else:
                F.append(make("adb_exposed", p, "adb", "AUTH requerido"))
        if "mqtt" in d and d["mqtt"].get("anonymous"):
            F.append(make("mqtt_anonymous", p, "mqtt", "CONNECT sin credenciales -> CONNACK 0"))
        if "rtsp" in d:
            F.append(make("rtsp_exposed", p, "rtsp", d["rtsp"].get("server", "")))
        if p in DB_PORTS or svc == "mysql":
            F.append(make("database_exposed", p, svc, s.get("banner", ""),
                          service=DB_PORTS.get(p, prod or svc)))
            if prod == "MySQL" and ver:
                add_cves("MySQL", ver, p, svc)
        if p in K8S_PORTS:
            F.append(make("k8s_exposed", p, svc, service=K8S_PORTS[p]))
        if p == 7547:
            F.append(make("tr069_exposed", p, "tr-069"))
        if p == 8291:
            F.append(make("winbox_exposed", p, "winbox"))
        if p == 8728:
            F.append(make("routeros_api", p, "routeros-api"))
        if p == 9100:
            F.append(make("jetdirect_open", p, "jetdirect"))
        if p in (111, 2049):
            if not any(f["fid"] == "nfs_exposed" for f in F):
                F.append(make("nfs_exposed", p, svc))
        if p == 873:
            F.append(make("rsync_exposed", p, "rsync"))
        if p == 623:
            F.append(make("ipmi_exposed", p, "ipmi"))
        # ---- versiones conocidas
        if prod and ver:
            add_cves(prod, ver, p, svc)
        # ---- HTTP
        http = s.get("http")
        if http:
            hdr = {k.lower(): v for k, v in http.get("headers", {}).items()}
            is_tls = bool(s.get("tls"))
            app = http.get("app") or http.get("title") or ""
            if http.get("password_form") and not is_tls:
                F.append(make("mgmt_cleartext", p, svc, f"Formulario de contraseña en http://{host['ip']}:{p}/",
                              app=f" ({app})" if app else ""))
            if not is_tls and http.get("auth", "").lower().startswith("basic"):
                F.append(make("http_basic_cleartext", p, svc, http["auth"]))
            if http.get("dir_listing"):
                F.append(make("dir_listing", p, svc, http.get("title", "")))
            if http.get("status") in (200, 401, 403) and http.get("body_len", 0) > 200:
                missing = [name for k, name in SEC_HEADERS.items() if k not in hdr]
                if "content-security-policy" in hdr and "frame-ancestors" in hdr["content-security-policy"]:
                    missing = [m for m in missing if m != "X-Frame-Options"]
                if len(missing) >= 2:
                    F.append(make("http_headers", p, svc, ", ".join(missing), missing=", ".join(missing)))
                if is_tls and "strict-transport-security" not in hdr:
                    F.append(make("hsts_missing", p, svc))
            banner_ver = " ".join(x for x in (http.get("server", ""), http.get("powered_by", "")) if x)
            if re.search(r"/\d", banner_ver):
                F.append(make("version_disclosure", p, svc, banner_ver, banner=banner_ver))
            for cprod, cver in cvedb.extract_components(banner_ver):
                add_cves(cprod, cver, p, svc)
            if http.get("routeros_version"):
                add_cves("MikroTik RouterOS", http["routeros_version"], p, svc)
            if http.get("app") in ("phpMyAdmin", "Jenkins", "Portainer", "Webmin", "Kibana", "Proxmox VE", "Cockpit"):
                F.append(make("admin_exposed", p, svc, http.get("title", ""), app=http["app"]))
        # ---- TLS
        tls = s.get("tls")
        if tls:
            if tls.get("legacy"):
                F.append(make("tls_legacy", p, svc, ", ".join(tls["legacy"]), protocols=" y ".join(tls["legacy"])))
            c = tls.get("cipher", "")
            reason = ""
            if c.startswith(("ADH", "AECDH")) or "anon" in c.lower():
                reason = "intercambio de claves anónimo, sin autenticar al servidor"
            elif "RC4" in c:
                reason = "RC4 está roto"
            elif "NULL" in c:
                reason = "sin cifrado"
            elif "DES-CBC3" in c or "3DES" in c:
                reason = "3DES es vulnerable a Sweet32"
            elif "EXP" in c:
                reason = "suite EXPORT de 40/56 bits"
            if reason:
                F.append(make("tls_weak_cipher", p, svc, c, cipher=c, reason=reason))
            cert = tls.get("cert") or {}
            if cert:
                na = cert.get("not_after_ts")
                if na:
                    days = int((na - time.time()) / 86400)
                    if days < 0:
                        F.append(make("cert_expired", p, svc, cert.get("not_after"), date=cert.get("not_after")))
                    elif days < 30:
                        F.append(make("cert_expiring", p, svc, cert.get("not_after"),
                                      days=days, date=cert.get("not_after")))
                if cert.get("self_signed"):
                    F.append(make("cert_self_signed", p, svc, cert.get("subject", ""), cn=cert.get("cn") or "sin CN"))
                weak = []
                if cert.get("key_alg", "").startswith("rsa") and cert.get("key_bits", 4096) < 2048:
                    weak.append(f"clave RSA de {cert['key_bits']} bits")
                if re.search(r"sha1With|md5With", cert.get("sig_alg", ""), re.I):
                    weak.append(f"firma {cert['sig_alg']}")
                if weak:
                    F.append(make("cert_weak", p, svc, "; ".join(weak),
                                  reason="El certificado usa " + " y ".join(weak) + "."))
    # ---- UDP / descubrimiento
    udp = host.get("udp", {})
    if udp.get("snmp"):
        F.append(make("snmp_default_community", 161, "snmp", udp["snmp"].get("sysdescr", ""),
                      community=udp["snmp"]["community"],
                      severity="critical" if udp["snmp"]["community"] == "private" else None))
    if udp.get("dns"):
        if udp["dns"].get("recursive"):
            F.append(make("dns_open_resolver", 53, "dns", "example.com resuelto con RA=1"))
        if udp["dns"].get("version"):
            F.append(make("dns_version", 53, "dns", udp["dns"]["version"], version=udp["dns"]["version"]))
            m = re.search(r"dnsmasq-([\d.]+)", udp["dns"]["version"])
            if m and cvedb.vt(m.group(1)) < cvedb.vt("2.83"):
                F.append({**make("eol_software", 53, "dns", udp["dns"]["version"], product="dnsmasq",
                                 version=m.group(1), detail="vulnerable a DNSpooq (CVE-2020-25681..25687)"),
                          "refs": ["CVE-2020-25681", "CVE-2020-25686"]})
    if udp.get("tftp"):
        F.append(make("tftp_open", 69, "tftp"))
    ssdp = host.get("upnp")
    if ssdp:
        if ssdp.get("igd"):
            F.append(make("upnp_igd", 1900, "upnp", ssdp.get("server", "")))
        else:
            F.append(make("upnp_exposed", 1900, "upnp", ssdp.get("server", ""), server=ssdp.get("server", "UPnP")))
        for cprod, cver in cvedb.extract_components(ssdp.get("server", "")):
            add_cves(cprod, cver, 1900, "upnp")
    F.extend(host.get("extra_findings", []))
    # Deduplica y ordena
    uniq, keys = [], set()
    for f in F:
        k = (f["fid"], f.get("port"))
        if k not in keys:
            keys.add(k)
            uniq.append(f)
    uniq.sort(key=lambda f: -knowledge.SEV_ORDER.get(f["severity"], 0))
    return uniq


def wifi_findings(wifi: dict | None) -> list[dict]:
    if not wifi:
        return []
    sec = (wifi.get("security") or "").upper()
    if not sec or sec in ("--", "ABIERTA"):
        sev, imp = "critical", "Red abierta: cualquiera puede conectarse y ver el tráfico no cifrado."
    elif "WEP" in sec:
        sev, imp = "critical", "WEP se rompe en minutos con herramientas públicas."
    elif "WPA1" in sec or sec.strip() == "WPA":
        sev, imp = "medium", ("El modo WPA (v1, TKIP) está permitido. TKIP es vulnerable y obliga a "
                              "degradar el rendimiento; un atacante puede forzar su uso.")
    else:
        return []
    f = make("wifi_weak", None, "wifi", wifi.get("security"), ssid=wifi.get("ssid", ""),
             security=wifi.get("security", "Abierta"), impact=imp)
    f["severity"] = sev
    f["impact"] = imp
    return [f]


def host_risk(findings: list[dict]) -> int:
    score = sum(knowledge.SEV_WEIGHT.get(f["severity"], 0) for f in findings)
    return min(100, score)


def network_score(hosts: list[dict], extra: list[dict]) -> dict:
    """Puntuación global 0-100 (100 = sin problemas) y nota A-F."""
    allf = [f for h in hosts for f in h.get("findings", [])] + extra
    counts = {s: 0 for s in knowledge.SEV_ORDER}
    for f in allf:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    penalty = counts["critical"] * 25 + counts["high"] * 10 + counts["medium"] * 4 + counts["low"] * 1
    score = max(0, round(100 - penalty ** 0.85)) if penalty else 100
    if counts["critical"]:
        score = min(score, 39)
    elif counts["high"]:
        score = min(score, 69)
    grade = "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 else "D" if score >= 40 else "F"
    return {"score": score, "grade": grade, "counts": counts}
