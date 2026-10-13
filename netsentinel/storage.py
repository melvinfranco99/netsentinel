"""Historial de escaneos y registro de dispositivos conocidos (SQLite)."""

import json
import sqlite3
import time
import zlib

from .config import DB_PATH, ensure_dirs

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started REAL, finished REAL, target TEXT, profile TEXT,
    summary TEXT, data BLOB
);
CREATE TABLE IF NOT EXISTS devices (
    key TEXT PRIMARY KEY, mac TEXT, last_ip TEXT, vendor TEXT, hostname TEXT,
    type TEXT, first_seen REAL, last_seen REAL, alias TEXT DEFAULT '', trusted INTEGER DEFAULT 0,
    times_seen INTEGER DEFAULT 0
);
"""


class Storage:
    def __init__(self, path=DB_PATH):
        ensure_dirs()
        self.path = path
        with self._db() as db:
            db.executescript(SCHEMA)

    def _db(self):
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        return db

    def save_scan(self, result: dict) -> int:
        blob = zlib.compress(json.dumps(result, default=_jsonable).encode(), 6)
        now = time.time()
        with self._db() as db:
            cur = db.execute(
                "INSERT INTO scans(started, finished, target, profile, summary, data) VALUES (?,?,?,?,?,?)",
                (result["started"], result["finished"], result["target"], result["profile"],
                 json.dumps(result["summary"]), blob))
            sid = cur.lastrowid
            for h in result["hosts"]:
                key = h.get("mac") or h["ip"]
                db.execute("""
                    INSERT INTO devices(key, mac, last_ip, vendor, hostname, type, first_seen, last_seen, times_seen)
                    VALUES (?,?,?,?,?,?,?,?,1)
                    ON CONFLICT(key) DO UPDATE SET last_ip=excluded.last_ip, vendor=excluded.vendor,
                        hostname=CASE WHEN excluded.hostname!='' THEN excluded.hostname ELSE devices.hostname END,
                        type=excluded.type, last_seen=excluded.last_seen, times_seen=devices.times_seen+1
                """, (key, h.get("mac", ""), h["ip"], h.get("vendor", ""), h.get("hostname", ""),
                      h.get("type", ""), now, now))
        return sid

    def list_scans(self, limit=100) -> list[dict]:
        with self._db() as db:
            rows = db.execute("SELECT id, started, finished, target, profile, summary FROM scans "
                              "ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [{**dict(r), "summary": json.loads(r["summary"] or "{}")} for r in rows]

    def get_scan(self, sid: int) -> dict | None:
        with self._db() as db:
            r = db.execute("SELECT id, data FROM scans WHERE id=?", (sid,)).fetchone()
        if not r:
            return None
        data = json.loads(zlib.decompress(r["data"]))
        data["id"] = r["id"]
        self._apply_aliases(data)
        return data

    def latest_scan(self) -> dict | None:
        with self._db() as db:
            r = db.execute("SELECT id FROM scans ORDER BY id DESC LIMIT 1").fetchone()
        return self.get_scan(r["id"]) if r else None

    def delete_scan(self, sid: int):
        with self._db() as db:
            db.execute("DELETE FROM scans WHERE id=?", (sid,))

    def known_devices(self) -> dict[str, dict]:
        with self._db() as db:
            rows = db.execute("SELECT * FROM devices").fetchall()
        return {r["key"]: dict(r) for r in rows}

    def update_device(self, key: str, alias: str | None = None, trusted: bool | None = None):
        with self._db() as db:
            db.execute("INSERT OR IGNORE INTO devices(key, first_seen, last_seen) VALUES (?,?,?)",
                       (key, time.time(), time.time()))
            if alias is not None:
                db.execute("UPDATE devices SET alias=? WHERE key=?", (alias[:80], key))
            if trusted is not None:
                db.execute("UPDATE devices SET trusted=? WHERE key=?", (1 if trusted else 0, key))

    def _apply_aliases(self, data: dict):
        known = self.known_devices()
        for h in data.get("hosts", []):
            k = known.get(h.get("mac") or h["ip"])
            if k:
                h["alias"] = k.get("alias") or ""
                h["trusted"] = bool(k.get("trusted"))
                h["first_seen"] = k.get("first_seen")


def _jsonable(o):
    if isinstance(o, (bytes, bytearray)):
        return o.hex()
    if isinstance(o, set):
        return sorted(o)
    return str(o)
