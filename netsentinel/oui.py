"""Resolución de fabricante a partir de la MAC (base de datos 'manuf' de Wireshark)."""

import threading
import urllib.request

from .config import OUI_PATH, OUI_URLS, ensure_dirs

# Respaldo mínimo por si no se ha podido descargar la base completa
_FALLBACK = {
    "B827EB": "Raspberry Pi", "DCA632": "Raspberry Pi", "E45F01": "Raspberry Pi",
    "D0EA11": "MikroTik", "4C5E0C": "MikroTik", "6C3B6B": "MikroTik",
    "3C2EFF": "Apple", "F0189B": "Apple", "001A11": "Google", "F4F5D8": "Google",
    "B4E62D": "Espressif", "240AC4": "Espressif", "A4CF12": "Espressif",
    "50C7BF": "TP-Link", "001E58": "D-Link", "90FD73": "ZTE", "B808CF": "Intel",
}

_lock = threading.Lock()
_db: dict[int, list[tuple[int, int, str]]] | None = None  # bits -> [(prefix, mask, vendor)]


def _load():
    global _db
    with _lock:
        if _db is not None:
            return
        db: dict[int, dict[int, str]] = {24: {}, 28: {}, 36: {}}
        try:
            with open(OUI_PATH, encoding="utf-8", errors="ignore") as fh:
                for line in fh:
                    if not line.strip() or line.startswith("#"):
                        continue
                    parts = line.rstrip("\n").split("\t")
                    if len(parts) < 2:
                        continue
                    pfx = parts[0].strip()
                    vendor = (parts[2] if len(parts) > 2 and parts[2].strip() else parts[1]).strip()
                    bits = 24
                    if "/" in pfx:
                        pfx, b = pfx.split("/", 1)
                        bits = int(b)
                    hexs = pfx.replace(":", "").replace("-", "").upper()
                    if bits not in db:
                        continue
                    val = int(hexs[: bits // 4].ljust(bits // 4, "0"), 16)
                    db[bits][val] = vendor
        except OSError:
            for k, v in _FALLBACK.items():
                db[24][int(k, 16)] = v
        _db = db


def lookup(mac: str) -> str:
    if not mac:
        return ""
    _load()
    h = mac.replace(":", "").replace("-", "").upper()
    if len(h) != 12:
        return ""
    for bits in (36, 28, 24):
        v = _db[bits].get(int(h[: bits // 4], 16))
        if v:
            return _clean(v)
    if is_random(mac):
        return "MAC aleatoria (privada)"
    return ""


def is_random(mac: str) -> bool:
    """Bit 'localmente administrada': típico de móviles con MAC privada."""
    try:
        return bool(int(mac.split(":")[0], 16) & 0x02)
    except (ValueError, IndexError):
        return False


def _clean(v: str) -> str:
    for suf in (", Inc.", " Inc.", ",Inc.", " Co.,Ltd.", " Co., Ltd.", " CO.,LTD", " Corporation",
                " Corp.", " Limited", " Ltd.", " LTD", " GmbH", " S.A.", " Technologies",
                " Technology", " Electronics"):
        if v.endswith(suf):
            v = v[: -len(suf)]
    return v.strip(" ,")


def has_database() -> bool:
    return OUI_PATH.exists() and OUI_PATH.stat().st_size > 100_000


def update_database() -> tuple[bool, str]:
    global _db
    ensure_dirs()
    last = ""
    for url in OUI_URLS:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "NetSentinel"})
            with urllib.request.urlopen(req, timeout=30) as r:
                data = r.read()
            if len(data) < 100_000:
                raise ValueError("respuesta demasiado pequeña")
            tmp = OUI_PATH.with_suffix(".tmp")
            tmp.write_bytes(data)
            tmp.replace(OUI_PATH)
            with _lock:
                _db = None
            return True, url
        except Exception as e:  # noqa: BLE001 - informamos del error al usuario
            last = str(e)
    return False, last
