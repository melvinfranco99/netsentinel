"""Auditoría de seguridad de este propio equipo (sin necesidad de root)."""

import base64
import glob
import os
import platform
import pwd
import re
import shutil
import stat
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from . import netinfo, vulns
from .util import run


def _c(cid, title, status, detail="", fix=None, severity="medium", category="Sistema"):
    return {"id": cid, "title": title, "status": status, "detail": detail, "fix": fix or [],
            "severity": severity, "category": category}


def check_firewall():
    active = [s for s in ("firewalld", "ufw", "nftables", "iptables", "ip6tables")
              if run(["systemctl", "is-active", s]).strip() == "active"]
    if active:
        return _c("firewall", "Cortafuegos activo", "pass", "Servicio activo: " + ", ".join(active),
                  category="Red")
    return _c("firewall", "Cortafuegos activo", "fail",
              "No hay ningún servicio de cortafuegos activo (firewalld, ufw, nftables, iptables).",
              ["Arch: sudo pacman -S ufw && sudo ufw default deny incoming && sudo ufw enable && sudo systemctl enable --now ufw",
               "Alternativa: sudo systemctl enable --now nftables (revisa /etc/nftables.conf, que por defecto bloquea la entrada)."],
              category="Red")


def check_listening():
    out = run(["ss", "-tulnpH"])
    exposed, local = [], 0
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue
        proto, addr = parts[0], parts[4]
        host, _, port = addr.rpartition(":")
        host = host.strip("[]").split("%")[0]
        if host in ("127.0.0.1", "::1") or host.startswith("127.") or host.startswith("fe80"):
            local += 1
            continue
        if proto == "udp" and port in ("68", "546", "5353", "5355"):
            continue
        proc = re.search(r'users:\(\("([^"]+)"', line)
        exposed.append(f"{proto}/{port} en {host or '*'}" + (f" ({proc.group(1)})" if proc else ""))
    if not exposed:
        return _c("listening", "Servicios expuestos a la red", "pass",
                  f"Ningún servicio escucha en interfaces de red ({local} solo en localhost).", category="Red")
    return _c("listening", "Servicios expuestos a la red", "warn",
              "Escuchando en la red: " + "; ".join(exposed[:15]),
              ["Revisa si cada servicio debe ser accesible desde otros equipos.",
               "Configúralos para escuchar solo en 127.0.0.1 o bloquéalos con el cortafuegos.",
               "Lista detallada: sudo ss -tulnp"], category="Red")


def _sshd_config() -> dict:
    conf = {}
    files = ["/etc/ssh/sshd_config"] + sorted(glob.glob("/etc/ssh/sshd_config.d/*.conf"))
    for f in files:
        try:
            for line in Path(f).read_text(errors="ignore").splitlines():
                line = line.split("#", 1)[0].strip()
                if not line or line.lower().startswith("match"):
                    continue
                k, _, v = line.partition(" ")
                conf.setdefault(k.lower(), v.strip())  # en sshd gana la primera aparición
        except OSError:
            pass
    return conf


def check_sshd():
    active = run(["systemctl", "is-active", "sshd"]).strip() == "active" or \
        run(["systemctl", "is-active", "ssh"]).strip() == "active"
    if not active:
        return [_c("sshd", "Servidor SSH", "pass", "El servidor SSH no está activo.", category="Acceso remoto")]
    conf = _sshd_config()
    res = []
    prl = conf.get("permitrootlogin", "prohibit-password")
    res.append(_c("ssh_root", "SSH: acceso como root", "fail" if prl == "yes" else "pass",
                  f"PermitRootLogin {prl}", ["Pon 'PermitRootLogin no' en /etc/ssh/sshd_config y reinicia sshd."],
                  "high", "Acceso remoto"))
    pa = conf.get("passwordauthentication", "yes")
    res.append(_c("ssh_pass", "SSH: autenticación por contraseña", "warn" if pa != "no" else "pass",
                  f"PasswordAuthentication {pa}",
                  ["Usa claves SSH (ssh-keygen -t ed25519; ssh-copy-id usuario@equipo).",
                   "Después pon 'PasswordAuthentication no' en sshd_config.",
                   "Considera fail2ban o sshguard para bloquear fuerza bruta."], "medium", "Acceso remoto"))
    return res


def check_updates():
    if shutil.which("checkupdates"):
        out = run(["checkupdates"], timeout=90)
        pkgs = [l.split()[0] for l in out.splitlines() if l.strip()]
        cmd = "sudo pacman -Syu"
    elif shutil.which("apt"):
        out = run(["apt", "list", "--upgradable"], timeout=60)
        pkgs = [l.split("/")[0] for l in out.splitlines() if "/" in l]
        cmd = "sudo apt update && sudo apt full-upgrade"
    elif shutil.which("dnf"):
        out = run(["dnf", "-q", "check-update"], timeout=90)
        pkgs = [l.split()[0] for l in out.splitlines() if l and not l.startswith(" ")]
        cmd = "sudo dnf upgrade --refresh"
    else:
        return _c("updates", "Actualizaciones pendientes", "info", "No se pudo determinar el gestor de paquetes.",
                  category="Actualizaciones")
    critical = [p for p in pkgs if re.match(r"^(linux|linux-lts|linux-zen|openssl|openssh|glibc|sudo|"
                                             r"systemd|firefox|chromium|curl|gnutls|nss|polkit|xz|"
                                             r"linux-image.*|openssh-server)$", p)]
    if not pkgs:
        return _c("updates", "Actualizaciones pendientes", "pass", "El sistema está al día.",
                  category="Actualizaciones")
    status = "fail" if critical or len(pkgs) > 40 else "warn"
    detail = f"{len(pkgs)} paquetes por actualizar"
    if critical:
        detail += ". Incluye componentes sensibles: " + ", ".join(critical[:10])
    return _c("updates", "Actualizaciones pendientes", status, detail, [f"Ejecuta: {cmd}"],
              "high" if critical else "medium", "Actualizaciones")


def check_reboot():
    rel = platform.release()
    if os.path.isdir("/usr/lib/modules") and not os.path.isdir(f"/usr/lib/modules/{rel}"):
        return _c("reboot", "Reinicio pendiente", "warn",
                  f"El kernel en ejecución ({rel}) ya no está instalado: se actualizó y falta reiniciar.",
                  ["Reinicia el equipo para usar el kernel parcheado."], "medium", "Actualizaciones")
    if os.path.exists("/var/run/reboot-required"):
        return _c("reboot", "Reinicio pendiente", "warn", "El sistema solicita un reinicio.",
                  ["Reinicia el equipo."], "medium", "Actualizaciones")
    return _c("reboot", "Reinicio pendiente", "pass", f"Kernel {rel} en uso.", category="Actualizaciones")


SYSCTLS = [
    ("kernel/randomize_va_space", "2", "ASLR completo", "high"),
    ("kernel/kptr_restrict", ("1", "2"), "Ocultar punteros del kernel", "low"),
    ("kernel/dmesg_restrict", "1", "Restringir dmesg a root", "low"),
    ("kernel/yama/ptrace_scope", ("1", "2", "3"), "Restringir ptrace", "low"),
    ("kernel/unprivileged_bpf_disabled", ("1", "2"), "BPF sin privilegios desactivado", "low"),
    ("net/ipv4/tcp_syncookies", "1", "Protección SYN flood", "low"),
    ("net/ipv4/conf/all/accept_redirects", "0", "Ignorar redirecciones ICMP", "low"),
    ("net/ipv4/conf/all/send_redirects", "0", "No enviar redirecciones ICMP", "low"),
    ("net/ipv4/conf/all/rp_filter", ("1", "2"), "Filtro de ruta inversa (anti-spoofing)", "low"),
    ("net/ipv4/conf/all/accept_source_route", "0", "Rechazar source routing", "low"),
    ("fs/protected_symlinks", "1", "Protección de enlaces simbólicos", "low"),
    ("fs/protected_hardlinks", "1", "Protección de enlaces duros", "low"),
]


def check_sysctl():
    bad, good = [], 0
    fixes = []
    for key, want, label, _sev in SYSCTLS:
        try:
            val = Path("/proc/sys/" + key).read_text().strip()
        except OSError:
            continue
        wants = want if isinstance(want, tuple) else (want,)
        if val in wants:
            good += 1
        else:
            bad.append(f"{label} ({key.replace('/', '.')} = {val})")
            fixes.append(f"{key.replace('/', '.')} = {wants[0]}")
    if not bad:
        return _c("sysctl", "Endurecimiento del kernel (sysctl)", "pass",
                  f"{good} parámetros correctos.", category="Kernel")
    return _c("sysctl", "Endurecimiento del kernel (sysctl)", "warn",
              f"{good} correctos, {len(bad)} mejorables: " + "; ".join(bad),
              ["Crea /etc/sysctl.d/99-hardening.conf con:"] + fixes +
              ["Aplica con: sudo sysctl --system"], "low", "Kernel")


def check_lsm():
    try:
        lsm = Path("/sys/kernel/security/lsm").read_text().strip()
    except OSError:
        lsm = ""
    if "apparmor" in lsm or "selinux" in lsm:
        return _c("lsm", "Control de acceso obligatorio (AppArmor/SELinux)", "pass", f"LSM activos: {lsm}",
                  category="Kernel")
    return _c("lsm", "Control de acceso obligatorio (AppArmor/SELinux)", "info",
              f"No hay AppArmor ni SELinux activos (LSM: {lsm or 'desconocido'}).",
              ["Arch: instala apparmor, añade 'lsm=landlock,lockdown,yama,integrity,apparmor,bpf' a la línea del kernel y habilita apparmor.service."],
              "low", "Kernel")


def check_secureboot():
    files = glob.glob("/sys/firmware/efi/efivars/SecureBoot-*")
    if not os.path.isdir("/sys/firmware/efi"):
        return _c("secureboot", "Secure Boot", "info", "Sistema arrancado en modo BIOS/Legacy.", category="Arranque",
                  severity="low")
    try:
        enabled = files and Path(files[0]).read_bytes()[-1] == 1
    except OSError:
        enabled = False
    if enabled:
        return _c("secureboot", "Secure Boot", "pass", "Secure Boot activado.", category="Arranque")
    return _c("secureboot", "Secure Boot", "info", "Secure Boot desactivado.",
              ["Opcional: configúralo con sbctl (Arch Wiki: 'Unified Extensible Firmware Interface/Secure Boot')."],
              "low", "Arranque")


def check_encryption():
    out = run(["lsblk", "-rno", "TYPE,FSTYPE,MOUNTPOINT"])
    crypt = any(("crypt" in l.split()[0]) or "crypto_LUKS" in l for l in out.splitlines() if l.split())
    if crypt:
        return _c("crypt", "Cifrado de disco", "pass", "Hay volúmenes cifrados con LUKS.", category="Datos")
    return _c("crypt", "Cifrado de disco", "warn",
              "No se ha detectado cifrado de disco (LUKS). Si roban o pierdes el equipo, los datos son legibles.",
              ["La forma recomendada es cifrar en la instalación (LUKS2 + dm-crypt).",
               "Como mínimo, cifra las carpetas sensibles (p. ej. con gocryptfs o un contenedor VeraCrypt)."],
              "medium", "Datos")


def check_groups():
    groups = run(["id", "-nG"]).split()
    res = []
    if "docker" in groups:
        res.append(_c("docker_group", "Usuario en el grupo 'docker'", "warn",
                      "Pertenecer al grupo docker equivale a tener permisos de root sin contraseña.",
                      ["Si no lo necesitas: sudo gpasswd -d $USER docker",
                       "Alternativa: usa Docker rootless o Podman."], "low", "Usuarios"))
    try:
        uid0 = [p.pw_name for p in pwd.getpwall() if p.pw_uid == 0 and p.pw_name != "root"]
    except Exception:  # noqa: BLE001
        uid0 = []
    res.append(_c("uid0", "Cuentas con UID 0 además de root", "fail" if uid0 else "pass",
                  ", ".join(uid0) if uid0 else "Solo root tiene UID 0.",
                  ["Elimina o cambia el UID de las cuentas: " + ", ".join(uid0)] if uid0 else [],
                  "critical", "Usuarios"))
    return res


def check_home():
    home = Path.home()
    res = []
    try:
        mode = home.stat().st_mode
        if mode & (stat.S_IROTH | stat.S_IXOTH):
            res.append(_c("home_perms", "Permisos de la carpeta personal", "warn",
                          f"{home} es accesible por otros usuarios ({oct(mode & 0o777)}).",
                          [f"chmod 700 {home}"], "low", "Datos"))
        else:
            res.append(_c("home_perms", "Permisos de la carpeta personal", "pass",
                          f"{oct(mode & 0o777)}", category="Datos"))
    except OSError:
        pass
    ssh = home / ".ssh"
    if ssh.is_dir():
        unenc = []
        for f in ssh.iterdir():
            if not f.is_file() or f.suffix == ".pub" or f.name in ("known_hosts", "config", "authorized_keys"):
                continue
            try:
                head = f.read_text(errors="ignore")[:4000]
            except OSError:
                continue
            if "BEGIN OPENSSH PRIVATE KEY" in head:
                b64 = "".join(l for l in head.splitlines() if not l.startswith("-----"))
                try:
                    raw = base64.b64decode(b64[:200] + "=" * (-len(b64[:200]) % 4))
                    if b"\x00\x00\x00\x04none" in raw[:60]:
                        unenc.append(f.name)
                except ValueError:
                    pass
            elif "BEGIN RSA PRIVATE KEY" in head or "BEGIN EC PRIVATE KEY" in head:
                if "ENCRYPTED" not in head:
                    unenc.append(f.name)
        if unenc:
            res.append(_c("ssh_keys", "Claves SSH privadas sin contraseña", "warn",
                          "Sin passphrase: " + ", ".join(unenc),
                          [f"Añade una contraseña: ssh-keygen -p -f ~/.ssh/{unenc[0]}",
                           "Usa ssh-agent para no tener que escribirla cada vez."], "medium", "Datos"))
        try:
            if ssh.stat().st_mode & 0o077:
                res.append(_c("ssh_dir", "Permisos de ~/.ssh", "warn", oct(ssh.stat().st_mode & 0o777),
                              ["chmod 700 ~/.ssh && chmod 600 ~/.ssh/id_*"], "medium", "Datos"))
        except OSError:
            pass
    return res


def check_wifi():
    w = netinfo.wifi_info()
    if not w:
        return []
    f = vulns.wifi_findings(w)
    if f:
        return [_c("wifi", f"Seguridad de la Wi-Fi «{w['ssid']}»", "fail" if f[0]["severity"] == "critical" else "warn",
                   f"Cifrado: {w['security']}. {f[0]['impact']}", f[0]["fix"], f[0]["severity"], "Red")]
    return [_c("wifi", f"Seguridad de la Wi-Fi «{w['ssid']}»", "pass", f"Cifrado: {w['security']}", category="Red")]


def audit() -> dict:
    checks = []
    with ThreadPoolExecutor(max_workers=8) as ex:
        futs = [ex.submit(fn) for fn in (check_firewall, check_listening, check_sshd, check_updates,
                                         check_reboot, check_sysctl, check_lsm, check_secureboot,
                                         check_encryption, check_groups, check_home, check_wifi)]
        for f in futs:
            try:
                r = f.result(timeout=120)
            except Exception as e:  # noqa: BLE001
                r = _c("error", "Comprobación fallida", "info", str(e))
            checks.extend(r if isinstance(r, list) else [r])
    weights = {"critical": 5, "high": 4, "medium": 3, "low": 1, "info": 0}
    total = sum(weights.get(c["severity"], 1) for c in checks if c["status"] != "info") or 1
    lost = sum(weights.get(c["severity"], 1) * (1 if c["status"] == "fail" else 0.5)
               for c in checks if c["status"] in ("fail", "warn"))
    score = round(100 * (1 - lost / total))
    order = {"fail": 0, "warn": 1, "info": 2, "pass": 3}
    checks.sort(key=lambda c: (order[c["status"]], -weights.get(c["severity"], 0)))
    return {"hostname": platform.node(), "kernel": platform.release(),
            "os": _os_name(), "score": score, "checks": checks}


def _os_name():
    try:
        for line in Path("/etc/os-release").read_text().splitlines():
            if line.startswith("PRETTY_NAME="):
                return line.split("=", 1)[1].strip('"')
    except OSError:
        pass
    return platform.system()
