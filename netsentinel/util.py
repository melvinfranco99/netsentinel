"""Utilidades compartidas."""

import ipaddress
import os
import shutil
import subprocess
import time

C_ENV = {**os.environ, "LC_ALL": "C", "LANG": "C"}


def run(cmd: list[str], timeout: float = 10, env=None) -> str:
    """Ejecuta un comando y devuelve stdout ('' si falla o no existe)."""
    if not shutil.which(cmd[0]):
        return ""
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                             env=env or C_ENV, stdin=subprocess.DEVNULL)
        return res.stdout
    except (subprocess.SubprocessError, OSError):
        return ""


def now() -> float:
    return time.time()


def is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def expand_target(target: str, limit: int) -> list[str]:
    """Acepta CIDR, IP suelta, rango 'a.b.c.d-e' o lista separada por comas."""
    ips: list[str] = []
    for chunk in target.replace(" ", "").split(","):
        if not chunk:
            continue
        if "/" in chunk:
            net = ipaddress.ip_network(chunk, strict=False)
            if net.version != 4:
                raise ValueError("Solo se admiten redes IPv4")
            if net.num_addresses > limit + 2:
                raise ValueError(f"La red {net} tiene demasiadas direcciones (máx. {limit})")
            hosts = list(net.hosts()) if net.prefixlen < 31 else list(net)
            ips.extend(str(h) for h in hosts)
        elif "-" in chunk:
            start, end = chunk.split("-", 1)
            a = ipaddress.IPv4Address(start)
            if "." in end:
                b = ipaddress.IPv4Address(end)
            else:
                b = ipaddress.IPv4Address(start.rsplit(".", 1)[0] + "." + end)
            if int(b) < int(a):
                a, b = b, a
            if int(b) - int(a) + 1 > limit:
                raise ValueError(f"Rango demasiado grande (máx. {limit})")
            ips.extend(str(ipaddress.IPv4Address(i)) for i in range(int(a), int(b) + 1))
        else:
            ips.append(str(ipaddress.IPv4Address(chunk)))
        if len(ips) > limit:
            raise ValueError(f"Demasiadas direcciones (máx. {limit})")
    seen = set()
    out = []
    for ip in ips:
        if ip not in seen:
            seen.add(ip)
            out.append(ip)
    if not out:
        raise ValueError("Objetivo vacío")
    return out


def raise_nofile():
    try:
        import resource
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        want = min(hard, 8192) if hard != resource.RLIM_INFINITY else 8192
        if soft < want:
            resource.setrlimit(resource.RLIMIT_NOFILE, (want, hard))
        return resource.getrlimit(resource.RLIMIT_NOFILE)[0]
    except (ImportError, ValueError, OSError):
        return 1024
