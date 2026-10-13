"""Sondas específicas por protocolo. Todas son de solo lectura y no prueban contraseñas
(salvo los accesos *anónimos* que el propio protocolo define: FTP anonymous, SNMP public)."""

import asyncio
import os
import re
import ssl
import struct
import tempfile
import time

from . import dnsproto
from .netio import TCPConn, http_get, insecure_ctx, udp_request, with_conn
from .util import run

# ------------------------------------------------------------------ TLS ---
async def tls_info(ip: str, port: int, sni: str | None = None) -> dict | None:
    try:
        conn = await TCPConn.open(ip, port, timeout=4, tls=True, server_hostname=sni)
    except Exception:  # noqa: BLE001
        return None
    try:
        so = conn.ssl_object()
        if so is None:
            return None
        info = {"version": so.version(), "cipher": (so.cipher() or ("", "", 0))[0],
                "cipher_bits": (so.cipher() or ("", "", 0))[2]}
        der = so.getpeercert(binary_form=True)
    finally:
        await conn.close()
    if der:
        info["cert"] = decode_cert(der)
    info["legacy"] = await legacy_protocols(ip, port)
    return info


async def legacy_protocols(ip, port) -> list[str]:
    found = []
    for name, ver in (("TLSv1.0", ssl.TLSVersion.TLSv1), ("TLSv1.1", ssl.TLSVersion.TLSv1_1)):
        try:
            ctx = insecure_ctx(minv=ver, maxv=ver)
            r, w = await asyncio.wait_for(asyncio.open_connection(ip, port, ssl=ctx), 4)
            neg = w.get_extra_info("ssl_object").version()
            w.close()
            if neg in ("TLSv1", "TLSv1.1"):
                found.append(name)
        except Exception:  # noqa: BLE001
            pass
    return found


_CERT_RE = {
    "subject": re.compile(r"^\s*Subject:\s*(.*)$", re.M),
    "issuer": re.compile(r"^\s*Issuer:\s*(.*)$", re.M),
    "not_before": re.compile(r"Not Before\s*:\s*(.*)$", re.M),
    "not_after": re.compile(r"Not After\s*:\s*(.*)$", re.M),
    "key_bits": re.compile(r"Public-Key:\s*\((\d+) bit\)"),
    "sig_alg": re.compile(r"Signature Algorithm:\s*(\S+)"),
    "key_alg": re.compile(r"Public Key Algorithm:\s*(\S+)"),
}


def decode_cert(der: bytes) -> dict:
    fd, path = tempfile.mkstemp(suffix=".der")
    try:
        os.write(fd, der)
        os.close(fd)
        txt = run(["openssl", "x509", "-inform", "DER", "-in", path, "-noout", "-text"], timeout=5)
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass
    out: dict = {}
    for k, rx in _CERT_RE.items():
        m = rx.search(txt)
        if m:
            out[k] = m.group(1).strip()
    out["san"] = re.findall(r"DNS:([^,\s]+)", txt)[:20]
    if "key_bits" in out:
        out["key_bits"] = int(out["key_bits"])
    out["self_signed"] = bool(out.get("subject")) and out.get("subject") == out.get("issuer")
    for k in ("not_before", "not_after"):
        if k in out:
            try:
                out[k + "_ts"] = time.mktime(time.strptime(out[k].replace("  ", " "),
                                                          "%b %d %H:%M:%S %Y %Z"))
            except ValueError:
                pass
    cn = re.search(r"CN\s*=\s*([^,/]+)", out.get("subject", ""))
    out["cn"] = cn.group(1).strip() if cn else ""
    return out


# ------------------------------------------------------------------ SSH ---
WEAK_SSH = {
    "kex": {"diffie-hellman-group1-sha1", "diffie-hellman-group-exchange-sha1",
            "diffie-hellman-group14-sha1", "gss-group1-sha1-*", "rsa1024-sha1"},
    "hostkey": {"ssh-dss", "ssh-rsa1"},
    "cipher": {"3des-cbc", "aes128-cbc", "aes192-cbc", "aes256-cbc", "blowfish-cbc",
               "cast128-cbc", "arcfour", "arcfour128", "arcfour256", "des-cbc",
               "rijndael-cbc@lysator.liu.se", "none"},
    "mac": {"hmac-md5", "hmac-md5-96", "hmac-sha1-96", "hmac-md5-etm@openssh.com",
            "hmac-md5-96-etm@openssh.com", "umac-32@openssh.com", "hmac-ripemd160", "none"},
}


async def ssh_info(ip, port) -> dict | None:
    async def go(conn: TCPConn):
        sent = False
        raw = await conn.recv_until(b"\n", timeout=2)
        if not raw:
            # Algunos servidores (p. ej. RouterOS) esperan a que el cliente hable primero
            await conn.send(b"SSH-2.0-NetSentinel_Audit\r\n")
            sent = True
            raw = await conn.recv_until(b"\n", timeout=3)
        line, _, rest = raw.partition(b"\n")
        banner = line.decode("latin-1").strip()
        if not banner.startswith("SSH-"):
            return {"banner": banner[:200]} if banner else None
        if not sent:
            await conn.send(b"SSH-2.0-NetSentinel_Audit\r\n")
        data = rest
        while len(data) < 5 or len(data) < 4 + struct.unpack(">I", data[:4])[0]:
            chunk = await conn.recv(8192, timeout=3)
            if not chunk:
                break
            data += chunk
        info = {"banner": banner.splitlines()[-1][:200]}
        try:
            plen = struct.unpack(">I", data[:4])[0]
            payload = data[5:4 + plen]
            if payload[0] != 20:  # SSH_MSG_KEXINIT
                return info
            off = 17
            lists = []
            for _ in range(10):
                ln = struct.unpack(">I", payload[off:off + 4])[0]
                lists.append(payload[off + 4:off + 4 + ln].decode("latin-1").split(","))
                off += 4 + ln
            info.update({"kex": lists[0], "hostkey": lists[1], "cipher": lists[2],
                         "mac": lists[4]})
            weak = {}
            for k, pat in WEAK_SSH.items():
                bad = [a for a in info[k] if a in pat]
                if bad:
                    weak[k] = bad
            info["weak"] = weak
            info["terrapin"] = ("chacha20-poly1305@openssh.com" in info["cipher"] or
                                any(m.endswith("-etm@openssh.com") for m in info["mac"])) and \
                "kex-strict-s-v00@openssh.com" not in info["kex"]
        except (struct.error, IndexError):
            pass
        return info
    return await with_conn(ip, port, go, timeout=4)


# ------------------------------------------------------------------ FTP ---
async def ftp_anonymous(ip, port) -> dict | None:
    async def go(conn: TCPConn):
        banner = (await conn.recv_until(b"\r\n", timeout=4)).decode("latin-1", "ignore").strip()
        if not banner.startswith("220"):
            return {"banner": banner}
        await conn.send(b"USER anonymous\r\n")
        r1 = (await conn.recv_until(b"\r\n", timeout=4)).decode("latin-1", "ignore")
        ok = False
        if r1.startswith("230"):
            ok = True
        elif r1.startswith("331"):
            await conn.send(b"PASS netsentinel@example.com\r\n")
            r2 = (await conn.recv_until(b"\r\n", timeout=5)).decode("latin-1", "ignore")
            ok = r2.startswith("230")
        tls = False
        await conn.send(b"QUIT\r\n")
        return {"banner": banner.splitlines()[0][:200], "anonymous": ok, "tls": tls}
    res = await with_conn(ip, port, go, timeout=4)
    if res and res.get("banner", "").startswith("220"):
        async def auth_tls(conn: TCPConn):
            await conn.recv_until(b"\r\n", timeout=3)
            await conn.send(b"AUTH TLS\r\n")
            r = (await conn.recv_until(b"\r\n", timeout=3)).decode("latin-1", "ignore")
            return r.startswith("234")
        res["tls"] = bool(await with_conn(ip, port, auth_tls, timeout=4))
    return res


# ------------------------------------------------------------------ VNC ---
async def vnc_info(ip, port) -> dict | None:
    async def go(conn: TCPConn):
        ver = await conn.recv(12, timeout=4)
        if not ver.startswith(b"RFB "):
            return None
        info = {"version": ver.decode().strip(), "no_auth": False, "types": []}
        await conn.send(ver)
        if ver[4:11] in (b"003.003",):
            data = await conn.recv(4, timeout=3)
            t = struct.unpack(">I", data)[0] if len(data) == 4 else 0
            info["types"] = [t]
        else:
            data = await conn.recv(64, timeout=3)
            if data:
                n = data[0]
                info["types"] = list(data[1:1 + n])
        info["no_auth"] = 1 in info["types"]
        return info
    return await with_conn(ip, port, go, timeout=4)


# ------------------------------------------------------------------ SMB ---
def _smb2_negotiate() -> bytes:
    hdr = b"\xfeSMB" + struct.pack("<HHIHHIIQIIQ16s", 64, 0, 0, 0, 1, 0, 0, 0, 0xFEFF, 0, 0, b"\x00" * 16)
    dialects = [0x0202, 0x0210, 0x0300, 0x0302]
    body = struct.pack("<HHHHI16sQ", 36, len(dialects), 1, 0, 0, os.urandom(16), 0)
    body += b"".join(struct.pack("<H", d) for d in dialects)
    pkt = hdr + body
    return struct.pack(">I", len(pkt)) + pkt


def _smb1_negotiate() -> bytes:
    dialects = b"\x02NT LM 0.12\x00"
    hdr = b"\xffSMB" + struct.pack("<BIBHH8sHHHHH", 0x72, 0, 0x18, 0x0001, 0, b"\x00" * 8, 0, 0, 0xFEFF, 0, 0)
    body = b"\x00" + struct.pack("<H", len(dialects)) + dialects
    pkt = hdr + body
    return struct.pack(">I", len(pkt)) + pkt


async def smb_info(ip, port=445) -> dict | None:
    async def neg2(conn: TCPConn):
        await conn.send(_smb2_negotiate())
        data = await conn.recv_all(limit=4096, timeout=3)
        if len(data) < 4 + 64 + 6 or data[4:8] != b"\xfeSMB":
            return None
        b = data[4 + 64:]
        sec_mode, dialect = struct.unpack("<HH", b[2:6])
        return {"smb2": True, "dialect": f"{dialect >> 8}.{(dialect & 0xff) >> 4}{dialect & 0xf}",
                "signing_required": bool(sec_mode & 0x02)}

    async def neg1(conn: TCPConn):
        await conn.send(_smb1_negotiate())
        data = await conn.recv_all(limit=4096, timeout=3)
        if len(data) > 40 and data[4:8] == b"\xffSMB":
            status = struct.unpack("<I", data[9:13])[0]
            word_count = data[36]
            if status == 0 and word_count > 0:
                idx = struct.unpack("<H", data[37:39])[0]
                return idx != 0xFFFF
        return False

    info = await with_conn(ip, port, neg2, timeout=4) or {}
    info["smb1"] = bool(await with_conn(ip, port, neg1, timeout=4))
    return info if info.get("smb2") or info["smb1"] else None


# ------------------------------------------------------------------ RDP ---
async def rdp_info(ip, port=3389) -> dict | None:
    async def go(conn: TCPConn):
        req = bytes.fromhex("030000130ee000000000000100080000000000")
        await conn.send(req)
        data = await conn.recv(64, timeout=4)
        if len(data) < 11 or data[0] != 3:
            return None
        info = {"rdp": True, "nla_required": None}
        if len(data) >= 19:
            typ = data[11]
            if typ == 0x02:      # RDP_NEG_RSP: aceptó seguridad RDP clásica
                info["nla_required"] = False
            elif typ == 0x03:    # RDP_NEG_FAILURE
                code = struct.unpack("<I", data[15:19])[0]
                info["nla_required"] = code in (5, 6)  # HYBRID_REQUIRED / SSL_WITH_USER_AUTH
        else:
            info["nla_required"] = False  # servidor antiguo sin negociación
        return info
    return await with_conn(ip, port, go, timeout=4)


# --------------------------------------------------------- Redis / etc ----
async def redis_info(ip, port) -> dict | None:
    async def go(conn: TCPConn):
        await conn.send(b"INFO server\r\n")
        data = (await conn.recv_all(limit=8192, timeout=2)).decode("latin-1", "ignore")
        if data.startswith("-NOAUTH") or "Authentication required" in data:
            return {"auth": True}
        if data.startswith("$") and "redis_version" in data:
            m = re.search(r"redis_version:([\d.]+)", data)
            return {"auth": False, "version": m.group(1) if m else ""}
        if data.startswith("-DENIED"):
            return {"auth": True, "protected_mode": True}
        return None
    return await with_conn(ip, port, go)


async def memcached_info(ip, port) -> dict | None:
    async def go(conn: TCPConn):
        await conn.send(b"stats\r\n")
        data = (await conn.recv_until(b"END", timeout=2)).decode("latin-1", "ignore")
        m = re.search(r"STAT version ([\d.]+)", data)
        return {"open": True, "version": m.group(1)} if m else None
    return await with_conn(ip, port, go)


async def mqtt_info(ip, port) -> dict | None:
    async def go(conn: TCPConn):
        client_id = b"netsentinel"
        vh = b"\x00\x04MQTT\x04\x02\x00\x3c"
        payload = struct.pack(">H", len(client_id)) + client_id
        rem = vh + payload
        await conn.send(b"\x10" + bytes([len(rem)]) + rem)
        data = await conn.recv(4, timeout=3)
        if len(data) >= 4 and data[0] == 0x20:
            await conn.send(b"\xe0\x00")
            return {"mqtt": True, "anonymous": data[3] == 0, "code": data[3]}
        return None
    return await with_conn(ip, port, go)


async def adb_info(ip, port=5555) -> dict | None:
    async def go(conn: TCPConn):
        payload = b"host::\x00"
        hdr = struct.pack("<6I", 0x4E584E43, 0x01000000, 4096, len(payload),
                          sum(payload) & 0xFFFFFFFF, 0x4E584E43 ^ 0xFFFFFFFF)
        await conn.send(hdr + payload)
        data = await conn.recv(256, timeout=3)
        if data[:4] == b"CNXN":
            body = data[24:].decode("latin-1", "ignore")
            return {"adb": True, "auth": False, "banner": body.strip("\x00")[:200]}
        if data[:4] == b"AUTH":
            return {"adb": True, "auth": True}
        return None
    return await with_conn(ip, port, go)


async def mongodb_info(ip, port=27017) -> dict | None:
    """Comando OP_QUERY isMaster (compatible con versiones antiguas y modernas)."""
    async def go(conn: TCPConn):
        bson = b"\x13\x00\x00\x00\x10isMaster\x00\x01\x00\x00\x00\x00"
        q = struct.pack("<i", 0) + b"admin.$cmd\x00" + struct.pack("<ii", 0, -1) + bson
        msg = struct.pack("<iiii", 16 + len(q), 1, 0, 2004) + q
        await conn.send(msg)
        data = await conn.recv(4096, timeout=3)
        if len(data) > 36 and b"ismaster" in data.lower():
            return {"mongodb": True}
        return None
    return await with_conn(ip, port, go)


async def docker_api(ip, port) -> dict | None:
    r = await http_get(ip, port, "/version", tls=port == 2376, timeout=3)
    if r and r["status"] == 200 and b"ApiVersion" in r["body"]:
        m = re.search(rb'"Version":"([^"]+)"', r["body"])
        return {"docker": True, "version": m.group(1).decode() if m else ""}
    return None


async def elastic_info(ip, port) -> dict | None:
    r = await http_get(ip, port, "/", timeout=3)
    if r and r["status"] == 200 and b"cluster_name" in r["body"]:
        m = re.search(rb'"number"\s*:\s*"([^"]+)"', r["body"])
        return {"open": True, "version": m.group(1).decode() if m else ""}
    if r and r["status"] == 401:
        return {"open": False}
    return None


async def rtsp_info(ip, port) -> dict | None:
    async def go(conn: TCPConn):
        await conn.send(f"OPTIONS rtsp://{ip}:{port}/ RTSP/1.0\r\nCSeq: 1\r\n\r\n".encode())
        data = (await conn.recv_until(b"\r\n\r\n", timeout=3)).decode("latin-1", "ignore")
        if data.startswith("RTSP/"):
            server = re.search(r"Server:\s*(.+)", data, re.I)
            return {"rtsp": True, "server": server.group(1).strip() if server else ""}
        return None
    return await with_conn(ip, port, go)


# ------------------------------------------------------------- UDP --------
def _ber_len(n):
    return bytes([n]) if n < 128 else bytes([0x81, n])


def _snmp_get(community: str) -> bytes:
    oid = bytes.fromhex("2b06010201010100")  # 1.3.6.1.2.1.1.1.0 sysDescr
    varbind = b"\x30" + _ber_len(len(oid) + 4) + b"\x06" + _ber_len(len(oid)) + oid + b"\x05\x00"
    vbl = b"\x30" + _ber_len(len(varbind)) + varbind
    reqid = b"\x02\x04" + os.urandom(4).replace(b"\x00", b"\x01")
    pdu_body = reqid + b"\x02\x01\x00\x02\x01\x00" + vbl
    pdu = b"\xa0" + _ber_len(len(pdu_body)) + pdu_body
    c = community.encode()
    msg = b"\x02\x01\x01" + b"\x04" + _ber_len(len(c)) + c + pdu  # versión 2c
    return b"\x30" + _ber_len(len(msg)) + msg


async def snmp_info(ip) -> dict | None:
    for community in ("public", "private"):
        data = await udp_request(ip, 161, _snmp_get(community), timeout=1.2, retries=1)
        if data and data[0] == 0x30:
            # El sysDescr es el último OCTET STRING del paquete
            descr = ""
            m = re.search(rb"\x2b\x06\x01\x02\x01\x01\x01\x00\x04(.)", data, re.S)
            if m:
                ln = m.group(1)[0]
                start = m.end()
                if ln & 0x80:
                    nb = ln & 0x7F
                    ln = int.from_bytes(data[start:start + nb], "big")
                    start += nb
                descr = data[start:start + ln].decode("utf-8", "replace")
            return {"community": community, "sysdescr": descr[:300]}
    return None


async def dns_info(ip) -> dict | None:
    q = dnsproto.build_query("example.com", dnsproto.T_A, rd=True)
    data = await udp_request(ip, 53, q, timeout=1.5, retries=1)
    if not data:
        return None
    info = {"dns": True, "recursive": False, "version": ""}
    try:
        p = dnsproto.parse(data)
        info["recursive"] = p["ra"] and p["ancount"] > 0
    except Exception:  # noqa: BLE001
        pass
    vq = dnsproto.build_query("version.bind", dnsproto.T_TXT, qclass=3, rd=False)
    vd = await udp_request(ip, 53, vq, timeout=1.2, retries=0)
    if vd:
        try:
            for r in dnsproto.parse(vd)["records"]:
                if r["type"] == dnsproto.T_TXT and r["value"]:
                    info["version"] = " ".join(r["value"])[:100]
        except Exception:  # noqa: BLE001
            pass
    return info


async def ntp_info(ip) -> dict | None:
    pkt = b"\x1b" + 47 * b"\x00"
    data = await udp_request(ip, 123, pkt, timeout=1.2, retries=0)
    if data and len(data) >= 48:
        return {"ntp": True, "stratum": data[1]}
    return None


async def tftp_info(ip) -> dict | None:
    pkt = b"\x00\x01" + b"netsentinel-probe.txt\x00octet\x00"
    data = await udp_request(ip, 69, pkt, timeout=1.2, retries=0)
    if data and len(data) >= 4 and data[1] in (3, 5):
        return {"tftp": True}
    return None
