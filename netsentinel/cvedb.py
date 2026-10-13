"""Base de datos local de vulnerabilidades conocidas por producto y versión.

No pretende sustituir a un escáner con feed de CVE completo: cubre las vulnerabilidades más
explotadas en redes domésticas y de pyme (routers, IoT, servidores web/SSH/FTP comunes).
"""

import re


def vt(version: str) -> tuple:
    nums = [int(x) for x in re.findall(r"\d+", version or "")]
    return tuple(nums) if nums else ()


def _lt(v, ref):
    return bool(v) and v < vt(ref)


def _between(v, lo, hi):  # lo <= v < hi
    return bool(v) and vt(lo) <= v < vt(hi)


# (producto exacto, condición, cves, severidad, título, solución)
RULES = [
    ("OpenSSH", lambda v: _lt(v, "4.4") or _between(v, "8.5", "9.8"), ["CVE-2024-6387"], "high",
     "regreSSHion: condición de carrera en sshd que permite ejecución remota como root",
     "Actualiza OpenSSH a 9.8p1 o superior. Mitigación temporal: LoginGraceTime 0 en sshd_config."),
    ("OpenSSH", lambda v: _between(v, "9.5", "9.9.2"), ["CVE-2025-26466"], "medium",
     "Denegación de servicio previa a la autenticación (consumo de memoria/CPU)",
     "Actualiza OpenSSH a 9.9p2 o superior."),
    ("OpenSSH", lambda v: _lt(v, "7.7"), ["CVE-2018-15473"], "medium",
     "Enumeración de usuarios válidos",
     "Actualiza OpenSSH (versión muy antigua con múltiples CVE)."),
    ("Dropbear", lambda v: _lt(v, "2016.74"), ["CVE-2016-7406", "CVE-2016-7407"], "critical",
     "Vulnerabilidades de cadena de formato / ejecución remota en Dropbear",
     "Actualiza el firmware del dispositivo (Dropbear ≥ 2022.83)."),
    ("Dropbear", lambda v: _between(v, "2016.74", "2022.83"), [], "medium",
     "Versión de Dropbear desactualizada",
     "Actualiza el firmware del dispositivo."),
    ("vsftpd", lambda v: v == vt("2.3.4"), ["CVE-2011-2523"], "critical",
     "Puerta trasera en vsftpd 2.3.4 (shell en el puerto 6200)",
     "Reinstala vsftpd desde una fuente oficial y actualiza a 3.0.5."),
    ("ProFTPD", lambda v: _lt(v, "1.3.6.1") or v == vt("1.3.6"), ["CVE-2019-12815", "CVE-2015-3306"], "critical",
     "mod_copy permite copiar ficheros arbitrarios sin autenticación",
     "Actualiza ProFTPD (≥ 1.3.8) o desactiva mod_copy."),
    ("Apache httpd", lambda v: v == vt("2.4.49"), ["CVE-2021-41773"], "critical",
     "Path traversal y ejecución remota en Apache 2.4.49",
     "Actualiza Apache httpd a la última 2.4.x."),
    ("Apache httpd", lambda v: v == vt("2.4.50"), ["CVE-2021-42013"], "critical",
     "Path traversal y ejecución remota en Apache 2.4.50",
     "Actualiza Apache httpd a la última 2.4.x."),
    ("Apache httpd", lambda v: _between(v, "2.4.0", "2.4.60"), ["CVE-2024-38476", "CVE-2023-25690"], "high",
     "Apache 2.4 desactualizado: request smuggling y fallos en mod_rewrite/mod_proxy",
     "Actualiza Apache httpd a 2.4.60 o posterior."),
    ("Apache httpd", lambda v: bool(v) and v < vt("2.4"), [], "high",
     "Apache 2.2 o anterior: sin soporte desde 2017",
     "Migra a Apache 2.4."),
    ("nginx", lambda v: _lt(v, "1.20.1"), ["CVE-2021-23017"], "high",
     "Fallo en el resolver de nginx (escritura fuera de límites)",
     "Actualiza nginx a una versión estable actual."),
    ("Microsoft IIS", lambda v: v == vt("6.0"), ["CVE-2017-7269"], "critical",
     "IIS 6.0 (Windows Server 2003): desbordamiento WebDAV con ejecución remota",
     "Migra a un Windows Server soportado."),
    ("Microsoft IIS", lambda v: v in (vt("7.0"), vt("7.5"), vt("8.0")), [], "high",
     "IIS de Windows Server 2008/2012 sin soporte",
     "Migra a un Windows Server soportado."),
    ("RomPager", lambda v: _lt(v, "4.34"), ["CVE-2014-9222"], "critical",
     "Misfortune Cookie: toma de control del router por una cookie manipulada",
     "Actualiza el firmware del router o sustitúyelo."),
    ("Boa", lambda v: True, [], "high",
     "Servidor web Boa abandonado desde 2005 (múltiples vulnerabilidades sin parchear, usado en ataques a IoT)",
     "Actualiza el firmware o sustituye el dispositivo."),
    ("GoAhead", lambda v: True, ["CVE-2017-17562"], "medium",
     "Servidor embebido GoAhead: versiones antiguas con ejecución remota",
     "Actualiza el firmware del dispositivo."),
    ("libupnp", lambda v: _lt(v, "1.6.18"), ["CVE-2012-5958", "CVE-2012-5959"], "critical",
     "Desbordamientos en libupnp (SSDP) explotables sin autenticación",
     "Actualiza el firmware o desactiva UPnP."),
    ("MiniUPnPd", lambda v: _lt(v, "2.0"), ["CVE-2013-0229", "CVE-2017-1000494"], "high",
     "MiniUPnPd desactualizado con fallos de memoria",
     "Actualiza el firmware del router y desactiva UPnP si no lo necesitas."),
    ("Exim", lambda v: _lt(v, "4.96.1"), ["CVE-2023-42115", "CVE-2019-10149"], "critical",
     "Ejecución remota de código en Exim",
     "Actualiza Exim a 4.96.1 o superior."),
    ("MikroTik RouterOS", lambda v: _lt(v, "6.42.1"), ["CVE-2018-14847"], "critical",
     "Winbox permite leer ficheros (incluidas las contraseñas) sin autenticación",
     "Actualiza RouterOS inmediatamente y cambia todas las contraseñas."),
    ("MikroTik RouterOS", lambda v: _lt(v, "6.49.7"), ["CVE-2023-30799"], "high",
     "Escalada de privilegios de admin a 'super-admin' (Winbox/HTTP)",
     "Actualiza RouterOS a 6.49.7+ o a la rama 7 estable."),
    ("MikroTik RouterOS", lambda v: bool(v) and v[0] == 6, [], "medium",
     "RouterOS 6 es una rama antigua; la rama 7 recibe todas las correcciones",
     "Planifica la actualización a RouterOS 7 estable."),
    ("Redis", lambda v: bool(v) and (_lt(v, "6.2.20") or _between(v, "7.0", "7.2.11")
                                      or _between(v, "7.4", "7.4.6") or _between(v, "8.0", "8.2.2")),
     ["CVE-2025-49844"], "critical",
     "RediShell: uso después de liberar en Lua que permite ejecución remota",
     "Actualiza Redis (6.2.20 / 7.2.11 / 7.4.6 / 8.2.2 o superiores) y exige autenticación."),
    ("PHP", lambda v: bool(v) and v < vt("8.2"), [], "high",
     "Versión de PHP sin soporte de seguridad",
     "Actualiza a PHP 8.3 o superior."),
    ("OpenSSL", lambda v: _between(v, "1.0.1", "1.0.1.7"), ["CVE-2014-0160"], "critical",
     "Heartbleed: lectura de memoria del servidor (claves privadas, contraseñas)",
     "Actualiza OpenSSL y regenera claves y certificados."),
    ("OpenSSL", lambda v: bool(v) and v < vt("3.0"), [], "high",
     "OpenSSL 1.x sin soporte",
     "Actualiza el software a una versión enlazada con OpenSSL 3."),
    ("MySQL", lambda v: bool(v) and v < vt("8.4"), [], "high",
     "MySQL sin soporte (5.7 y 8.0 han llegado al fin de vida)",
     "Actualiza a MySQL 8.4 LTS."),
    ("Elasticsearch", lambda v: bool(v) and v < vt("7.17"), [], "high",
     "Elasticsearch sin soporte",
     "Actualiza a Elasticsearch 8.x."),
    ("Memcached", lambda v: _lt(v, "1.5.6"), ["CVE-2018-1000115"], "medium",
     "UDP habilitado por defecto: amplificación DDoS",
     "Actualiza Memcached o arranca con -U 0."),
]


def match(product: str, version: str) -> list[dict]:
    out = []
    v = vt(version)
    for prod, cond, cves, sev, title, fix in RULES:
        if prod != product:
            continue
        try:
            hit = cond(v)
        except (TypeError, IndexError):
            hit = False
        if hit:
            out.append({"cves": cves, "severity": sev, "title": title, "fix": fix,
                        "product": product, "version": version})
    return out


def extract_components(text: str) -> list[tuple[str, str]]:
    """Extrae (producto, versión) de cabeceras tipo Server / X-Powered-By."""
    comps = []
    for rx, prod in ((r"PHP/([\d.]+)", "PHP"), (r"OpenSSL/([\d.]+[a-z]?)", "OpenSSL"),
                     (r"Apache/([\d.]+)", "Apache httpd"), (r"nginx/([\d.]+)", "nginx"),
                     (r"Microsoft-IIS/([\d.]+)", "Microsoft IIS"), (r"RomPager/([\d.]+)", "RomPager"),
                     (r"MiniUPnPd/([\d.]+)", "MiniUPnPd"),
                     (r"Portable SDK for UPnP devices/([\d.]+)", "libupnp"), (r"Boa/([\w.]+)", "Boa"),
                     (r"GoAhead", "GoAhead")):
        m = re.search(rx, text or "", re.I)
        if m:
            ver = m.group(1) if m.groups() else ""
            if prod == "OpenSSL" and re.search(r"[a-z]$", ver):
                # 1.0.1g -> 1.0.1.7 para poder comparar letras de parche
                ver = ver[:-1] + "." + str(ord(ver[-1]) - 96)
            comps.append((prod, ver))
    return comps
