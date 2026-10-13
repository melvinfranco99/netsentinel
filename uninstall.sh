#!/usr/bin/env bash
# Desinstala NetSentinel. Usa --purge para borrar también el historial.
set -euo pipefail
DATA="${XDG_DATA_HOME:-$HOME/.local/share}/netsentinel"
rm -f "$HOME/.local/bin/netsentinel"
if [[ "${1:-}" == "--purge" ]]; then
  rm -rf "$DATA" "${XDG_STATE_HOME:-$HOME/.local/state}/netsentinel"
  echo "NetSentinel y sus datos eliminados."
else
  rm -rf "$DATA/app"
  echo "NetSentinel desinstalado (historial conservado en $DATA; usa --purge para borrarlo)."
fi
