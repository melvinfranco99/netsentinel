"""Rutas y ajustes globales."""

import os
from pathlib import Path

APP_ID = "netsentinel"

_xdg_data = Path(os.environ.get("XDG_DATA_HOME") or Path.home() / ".local/share")
_xdg_state = Path(os.environ.get("XDG_STATE_HOME") or Path.home() / ".local/state")

DATA_DIR = _xdg_data / APP_ID
STATE_DIR = _xdg_state / APP_ID
DB_PATH = DATA_DIR / "netsentinel.db"
OUI_PATH = DATA_DIR / "manuf"

OUI_URLS = [
    "https://www.wireshark.org/download/automated/data/manuf",
    "https://raw.githubusercontent.com/wireshark/wireshark/master/manuf",
]

# Máximo de direcciones que se permiten en un objetivo (equivale a un /20).
MAX_TARGET_HOSTS = 4096


def ensure_dirs():
    for d in (DATA_DIR, STATE_DIR):
        d.mkdir(parents=True, exist_ok=True, mode=0o700)
