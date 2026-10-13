#!/usr/bin/env bash
# Instalador de NetSentinel (instalación de usuario, sin root)
#   ./install.sh            desde el repositorio clonado
#   curl -fsSL https://raw.githubusercontent.com/melvinfranco99/netsentinel/main/install.sh | bash
set -euo pipefail

REPO="https://github.com/melvinfranco99/netsentinel.git"
PREFIX="${XDG_DATA_HOME:-$HOME/.local/share}/netsentinel"
BIN="$HOME/.local/bin"

say() { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
die() { printf '\033[1;31mError:\033[0m %s\n' "$*" >&2; exit 1; }

command -v python3 >/dev/null || die "python3 no está instalado"
python3 -c 'import sys; sys.exit(sys.version_info < (3, 10))' || die "se necesita Python 3.10 o superior"
command -v ip >/dev/null || die "falta el comando 'ip' (paquete iproute2)"

SRC="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd || true)"
if [[ -z "$SRC" || ! -d "$SRC/netsentinel" ]]; then
  command -v git >/dev/null || die "git no está instalado"
  TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
  say "Descargando NetSentinel…"
  git clone --depth 1 -q "$REPO" "$TMP/netsentinel"
  SRC="$TMP/netsentinel"
fi

say "Instalando en $PREFIX"
mkdir -p "$PREFIX" "$BIN"
rm -rf "$PREFIX/app"
mkdir -p "$PREFIX/app"
cp -r "$SRC/netsentinel" "$PREFIX/app/"
find "$PREFIX/app" -name '__pycache__' -prune -exec rm -rf {} +

cat > "$BIN/netsentinel" <<LAUNCH
#!/bin/sh
PYTHONPATH="$PREFIX/app\${PYTHONPATH:+:\$PYTHONPATH}" exec python3 -m netsentinel "\$@"
LAUNCH
chmod +x "$BIN/netsentinel"

say "Descargando la base de fabricantes MAC (Wireshark manuf)…"
"$BIN/netsentinel" update-oui || echo "  (sin conexión: se usará una lista mínima; reintenta con 'netsentinel update-oui')"

for opt in nmcli checkupdates openssl ss; do
  command -v "$opt" >/dev/null || echo "  Aviso: '$opt' no está instalado; algunas comprobaciones se omitirán."
done

case ":$PATH:" in *":$BIN:"*) ;; *) echo "  Añade $BIN a tu PATH (p. ej. en ~/.zshrc: export PATH=\"\$HOME/.local/bin:\$PATH\")";; esac
say "¡Listo! Prueba:  netsentinel scan    ·    netsentinel audit    ·    netsentinel --help"
