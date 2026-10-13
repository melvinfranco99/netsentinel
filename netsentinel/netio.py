"""Primitivas de red asíncronas (TCP/UDP) usadas por todos los módulos."""

import asyncio
import socket
import ssl
import time


async def udp_request(ip: str, port: int, payload: bytes, timeout: float = 1.5,
                      retries: int = 1, bufsize: int = 4096) -> bytes | None:
    loop = asyncio.get_running_loop()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setblocking(False)
    try:
        for _ in range(retries + 1):
            try:
                sock.sendto(payload, (ip, port))
                data, _addr = await asyncio.wait_for(loop.sock_recvfrom(sock, bufsize), timeout)
                return data
            except (asyncio.TimeoutError, TimeoutError):
                continue
            except OSError:
                return None
        return None
    finally:
        sock.close()


async def udp_collect(dest: tuple[str, int], payload: bytes, duration: float = 2.5,
                      ttl: int = 2, resend: int = 1) -> list[tuple[bytes, str]]:
    """Envía a multicast/broadcast y recoge todas las respuestas durante 'duration' s."""
    loop = asyncio.get_running_loop()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setblocking(False)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, ttl)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    out = []
    try:
        sock.bind(("", 0))
        end = time.monotonic() + duration
        sends = [time.monotonic() + i * (duration / (resend + 1)) for i in range(resend + 1)]
        while True:
            now = time.monotonic()
            while sends and sends[0] <= now:
                sends.pop(0)
                try:
                    sock.sendto(payload, dest)
                except OSError:
                    pass
            left = end - now
            if left <= 0:
                break
            wait = min(left, (sends[0] - now) if sends else left)
            try:
                data, addr = await asyncio.wait_for(loop.sock_recvfrom(sock, 9000), max(wait, 0.01))
                out.append((data, addr[0]))
            except (asyncio.TimeoutError, TimeoutError):
                pass
            except OSError:
                break
    finally:
        sock.close()
    return out


class TCPConn:
    """Pequeño envoltorio sobre StreamReader/Writer con timeouts."""

    def __init__(self, reader, writer):
        self.r, self.w = reader, writer

    @classmethod
    async def open(cls, ip, port, timeout=3.0, tls=False, server_hostname=None):
        ctx = None
        if tls:
            ctx = insecure_ctx()
        r, w = await asyncio.wait_for(
            asyncio.open_connection(ip, port, ssl=ctx,
                                    server_hostname=(server_hostname or ip) if tls else None),
            timeout)
        return cls(r, w)

    async def recv(self, n=4096, timeout=2.0) -> bytes:
        try:
            return await asyncio.wait_for(self.r.read(n), timeout)
        except (asyncio.TimeoutError, TimeoutError, ConnectionError, OSError, ssl.SSLError):
            return b""

    async def recv_until(self, marker: bytes, limit=16384, timeout=3.0) -> bytes:
        buf = b""
        end = time.monotonic() + timeout
        while marker not in buf and len(buf) < limit:
            left = end - time.monotonic()
            if left <= 0:
                break
            chunk = await self.recv(4096, left)
            if not chunk:
                break
            buf += chunk
        return buf

    async def recv_all(self, limit=65536, timeout=3.0) -> bytes:
        buf = b""
        end = time.monotonic() + timeout
        while len(buf) < limit:
            left = end - time.monotonic()
            if left <= 0:
                break
            chunk = await self.recv(8192, left)
            if not chunk:
                break
            buf += chunk
        return buf

    async def send(self, data: bytes):
        self.w.write(data)
        try:
            await asyncio.wait_for(self.w.drain(), 3)
        except (asyncio.TimeoutError, TimeoutError):
            pass

    def ssl_object(self):
        return self.w.get_extra_info("ssl_object")

    async def close(self):
        try:
            self.w.close()
            await asyncio.wait_for(self.w.wait_closed(), 1)
        except Exception:  # noqa: BLE001
            pass


async def with_conn(ip, port, fn, timeout=3.0, tls=False):
    """Abre conexión, ejecuta fn(conn) y cierra. Devuelve None si no conecta."""
    try:
        conn = await TCPConn.open(ip, port, timeout=timeout, tls=tls)
    except Exception:  # noqa: BLE001
        return None
    try:
        return await fn(conn)
    except Exception:  # noqa: BLE001
        return None
    finally:
        await conn.close()


def insecure_ctx(minv=None, maxv=None) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.set_ciphers("ALL:@SECLEVEL=0")
    except ssl.SSLError:
        pass
    if minv:
        ctx.minimum_version = minv
    if maxv:
        ctx.maximum_version = maxv
    return ctx


async def http_get(ip, port, path="/", tls=False, timeout=4.0, host=None, method="GET",
                   limit=262144) -> dict | None:
    """Petición HTTP/1.0 mínima. Devuelve {status, headers, body} o None."""
    async def go(conn):
        req = (f"{method} {path} HTTP/1.0\r\nHost: {host or ip}\r\n"
               "User-Agent: Mozilla/5.0 (NetSentinel security audit)\r\n"
               "Accept: */*\r\nConnection: close\r\n\r\n").encode()
        await conn.send(req)
        raw = await conn.recv_all(limit=limit, timeout=timeout)
        return parse_http(raw)
    return await with_conn(ip, port, go, timeout=timeout, tls=tls)


def parse_http(raw: bytes) -> dict | None:
    if not raw.startswith(b"HTTP/"):
        return None
    head, _, body = raw.partition(b"\r\n\r\n")
    lines = head.decode("latin-1").split("\r\n")
    try:
        status = int(lines[0].split()[1])
    except (IndexError, ValueError):
        status = 0
    headers: dict[str, str] = {}
    for ln in lines[1:]:
        if ":" in ln:
            k, v = ln.split(":", 1)
            k = k.strip().lower()
            headers[k] = (headers[k] + ", " + v.strip()) if k in headers else v.strip()
    return {"status": status, "status_line": lines[0], "headers": headers, "body": body}
