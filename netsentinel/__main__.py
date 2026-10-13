"""Interfaz de línea de comandos de NetSentinel."""

import argparse
import json
import os
import sys
import time
from pathlib import Path

from . import __version__
from .config import ensure_dirs

# ------------------------------------------------------------------ colores
_COLOR = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def c(text, code):
    return f"\033[{code}m{text}\033[0m" if _COLOR else str(text)


SEV_STYLE = {"critical": ("CRÍTICA", "1;97;41"), "high": ("ALTA", "1;31"), "medium": ("MEDIA", "1;33"),
             "low": ("BAJA", "1;34"), "info": ("INFO", "2")}
GRADE_STYLE = {"A": "1;32", "B": "1;32", "C": "1;33", "D": "1;31", "F": "1;97;41"}


def sev(s):
    label, code = SEV_STYLE.get(s, (s, "0"))
    return c(f"{label:<7}", code)


def title(t):
    print("\n" + c(t, "1;36"))
    print(c("─" * min(78, len(t) + 4), "2"))


def bar(n, total, width=24):
    full = int(round(width * n / total)) if total else 0
    return "█" * full + c("░" * (width - full), "2")


# ------------------------------------------------------------------ escaneo
def cmd_scan(args):
    from . import netinfo
    from .report import to_csv, to_html
    from .scanner import ScanJob
    from .storage import Storage

    target = args.target or netinfo.snapshot()["suggested_target"]
    job = ScanJob(target, args.profile, args.ports or "", None if args.no_save else Storage())
    print(c(f"NetSentinel {__version__}", "1") + f" · objetivo {c(target, '1')} · perfil {args.profile}")
    th = job.start()
    last = ""
    try:
        while th.is_alive():
            time.sleep(0.5)
            s = job.snapshot()
            line = f"\r{bar(s['percent'], 100, 20)} {s['percent']:5.1f}%  {s['phase_label'][:34]:<34} {s['hosts_found']:>3} disp."
            if line != last and sys.stderr.isatty():
                sys.stderr.write(line)
                last = line
    except KeyboardInterrupt:
        job.cancel.set()
        sys.stderr.write("\nCancelando…\n")
        th.join()
    if sys.stderr.isatty():
        sys.stderr.write("\r" + " " * 90 + "\r")
    r = job.result
    if not r:
        print("Error:", job.state.get("error"), file=sys.stderr)
        return 1
    print_result(r, args.detail)
    for path, fn, label in ((args.json, lambda d: json.dumps(d, ensure_ascii=False, indent=1, default=str), "JSON"),
                            (args.html, to_html, "Informe HTML"), (args.csv, to_csv, "CSV")):
        if path:
            Path(path).write_text(fn(r), encoding="utf-8")
            print(f"{label} guardado en {c(path, '1')}")
    if r.get("id"):
        print(c(f"\nGuardado en el historial como escaneo #{r['id']} "
                f"(netsentinel report {r['id']} --html informe.html)", "2"))
    return 0


def print_result(r, detail=False):
    from .classify import TYPES
    sc = r["score"]
    net = r.get("network", {})
    title(f"Resumen · {r['target']}")
    print(f"  Nota de seguridad   {c(' ' + sc['grade'] + ' ', GRADE_STYLE[sc['grade']])}  {sc['score']}/100")
    print(f"  Dispositivos        {len(r['hosts'])}  ({r['summary'].get('new_devices', 0)} nuevos)")
    print(f"  Puertos abiertos    {r['summary']['open_ports']}  ({r.get('ports_scanned', 0)} analizados por equipo)")
    print(f"  Duración            {r.get('duration')} s")
    if net.get("wifi"):
        w = net["wifi"]
        print(f"  Wi-Fi               {w['ssid']} · {w['security']} · señal {w['signal']}% · canal {w['channel']}")
    counts = sc["counts"]
    total = sum(counts[k] for k in ("critical", "high", "medium", "low")) or 1
    print()
    for k in ("critical", "high", "medium", "low"):
        print(f"  {sev(k)} {bar(counts[k], total)} {counts[k]}")

    title("Dispositivos")
    print(c(f"  {'IP':<16}{'NOMBRE':<26}{'TIPO':<20}{'FABRICANTE':<20}{'SO':<22}RIESGO", "2"))
    for h in r["hosts"]:
        name = (h.get("alias") or h.get("hostname") or "—")[:24]
        worst = max(h["findings"], key=lambda f: ["info", "low", "medium", "high", "critical"].index(f["severity"]),
                    default=None)
        risk = sev(worst["severity"]) if worst and worst["severity"] != "info" else c("OK", "32")
        tags = (c(" NUEVO", "1;35") if h.get("new") else "") + (c(" (tú)", "2") if h.get("is_self") else "")
        print(f"  {h['ip']:<16}{name:<26}{TYPES.get(h.get('type'), '')[:18]:<20}"
              f"{(h.get('vendor') or '—')[:18]:<20}{(h.get('os') or '—')[:20]:<22}{risk}{tags}")
        if h["services"]:
            svcs = ", ".join(f"{s['port']}/{s.get('service') or '?'}" + (f" {s['product']}" if s.get("product") else "")
                             + (f" {s['version']}" if s.get("version") else "") for s in h["services"])
            print(c(f"  {'':<16}↳ {svcs[:150]}", "2"))

    groups = {}
    for h in r["hosts"]:
        for f in h["findings"]:
            groups.setdefault((f["fid"], f["title"]), {"f": f, "where": []})["where"].append(
                h["ip"] + (f":{f['port']}" if f.get("port") else ""))
    for f in r.get("network_findings", []):
        groups.setdefault((f["fid"], f["title"]), {"f": f, "where": ["Wi-Fi"]})
    order = ["critical", "high", "medium", "low", "info"]
    items = sorted(groups.values(), key=lambda g: order.index(g["f"]["severity"]))
    items = [g for g in items if g["f"]["severity"] != "info" or detail]
    title("Vulnerabilidades y cómo solucionarlas")
    if not items:
        print(c("  No se han encontrado problemas. ¡Buen trabajo!", "32"))
    for g in items:
        f = g["f"]
        print(f"\n  {sev(f['severity'])} {c(f['title'], '1')}  {c(f['category'], '2')}")
        print(f"          Afecta a: {', '.join(g['where'])}")
        if detail:
            print(f"          {f['description']}")
            print(f"          {c('Impacto:', '1')} {f['impact']}")
        for i, step in enumerate(f["fix"], 1):
            print(f"          {c(str(i) + '.', '36')} {step}")
        if detail and f.get("refs"):
            print(c(f"          Ref: {' · '.join(f['refs'][:4])}", "2"))


# ------------------------------------------------------------------ otros
def cmd_audit(args):
    from .localaudit import audit
    r = audit()
    icon = {"pass": c("✔", "32"), "warn": c("!", "33"), "fail": c("✘", "31"), "info": c("i", "2")}
    title(f"Auditoría de {r['hostname']} · {r['os']} · kernel {r['kernel']}")
    print(f"  Puntuación: {c(str(r['score']) + '/100', '1')}\n")
    for ch in r["checks"]:
        print(f"  {icon[ch['status']]} {c(ch['title'], '1')}: {ch['detail']}")
        if ch["status"] in ("fail", "warn"):
            for step in ch["fix"]:
                print(f"      {c('→', '36')} {step}")
    return 0


def cmd_net(args):
    from . import netinfo
    n = netinfo.snapshot()
    title(f"Red de {n['hostname']}")
    for i in n["interfaces"]:
        print(f"  {i['name']:<16} {i['ip']}/{i['prefix']:<4} {i['mac']:<18} {i['kind']}{'' if i['up'] else ' (inactiva)'}")
    print(f"\n  Puerta de enlace  {n.get('gateway') or '—'} ({n.get('gateway_dev') or ''})")
    print(f"  DNS               {', '.join(n['dns']) or '—'}")
    print(f"  Red sugerida      {n['suggested_target']}")
    if n.get("wifi"):
        w = n["wifi"]
        print(f"  Wi-Fi             {w['ssid']} · {w['security']} · señal {w['signal']}% · canal {w['channel']} · {w['rate']}")
    return 0


def cmd_history(args):
    from .storage import Storage
    scans = Storage().list_scans(args.limit)
    if not scans:
        print("Todavía no hay escaneos guardados.")
        return 0
    title("Historial de escaneos")
    print(c(f"  {'#':<5}{'FECHA':<18}{'OBJETIVO':<20}{'PERFIL':<12}{'DISP.':<7}{'PUERTOS':<9}NOTA", "2"))
    for s in scans:
        sm = s["summary"]
        g = sm.get("grade", "?")
        print(f"  {s['id']:<5}{time.strftime('%d/%m/%Y %H:%M', time.localtime(s['started'])):<18}"
              f"{s['target'][:18]:<20}{s['profile']:<12}{sm.get('hosts', 0):<7}{sm.get('open_ports', 0):<9}"
              f"{c(' ' + g + ' ', GRADE_STYLE.get(g, '0'))} {sm.get('score', '')}")
    return 0


def cmd_report(args):
    from .report import to_csv, to_html
    from .storage import Storage
    st = Storage()
    r = st.latest_scan() if args.id == "ultimo" else st.get_scan(int(args.id)) if args.id.isdigit() else None
    if not r:
        print("Escaneo no encontrado.", file=sys.stderr)
        return 1
    if not (args.html or args.csv or args.json):
        print_result(r, args.detail)
    for path, fn in ((args.html, to_html), (args.csv, to_csv),
                     (args.json, lambda d: json.dumps(d, ensure_ascii=False, indent=1, default=str))):
        if path:
            Path(path).write_text(fn(r), encoding="utf-8")
            print(f"Guardado en {c(path, '1')}")
    return 0


def cmd_update_oui(args):
    from .oui import update_database
    ok, msg = update_database()
    print(("Base de fabricantes actualizada desde " if ok else "Error: ") + msg)
    return 0 if ok else 1


def main(argv=None):
    p = argparse.ArgumentParser(
        prog="netsentinel",
        description="Escáner de red y auditor de seguridad. Úsalo solo en redes que te pertenezcan o "
                    "que tengas permiso para analizar.",
        epilog="Ejemplos:\n  netsentinel scan\n  netsentinel scan 192.168.1.0/24 -p completo --html informe.html\n"
               "  netsentinel audit\n  netsentinel report ultimo --html informe.html",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--version", action="version", version=f"NetSentinel {__version__}")
    sub = p.add_subparsers(dest="cmd")

    s = sub.add_parser("scan", help="escanear la red (por defecto, tu red local)")
    s.add_argument("target", nargs="?", help="CIDR, IP, rango (10.0.0.1-50) o lista separada por comas")
    s.add_argument("-p", "--profile", default="estandar",
                   choices=["rapido", "estandar", "completo", "descubrimiento"])
    s.add_argument("--ports", help="puertos personalizados, p. ej. 22,80,8000-8100")
    s.add_argument("-d", "--detail", action="store_true", help="mostrar descripción, impacto e info")
    s.add_argument("--html", help="guardar informe HTML")
    s.add_argument("--csv", help="guardar CSV")
    s.add_argument("--json", help="guardar JSON")
    s.add_argument("--no-save", action="store_true", help="no guardar en el historial")
    s.set_defaults(fn=cmd_scan)

    sub.add_parser("audit", help="auditar la seguridad de este equipo").set_defaults(fn=cmd_audit)
    sub.add_parser("net", help="mostrar información de la red local").set_defaults(fn=cmd_net)
    h = sub.add_parser("history", help="historial de escaneos")
    h.add_argument("-n", "--limit", type=int, default=30)
    h.set_defaults(fn=cmd_history)
    r = sub.add_parser("report", help="ver o exportar un escaneo guardado")
    r.add_argument("id", help="número de escaneo o 'ultimo'")
    r.add_argument("-d", "--detail", action="store_true")
    r.add_argument("--html")
    r.add_argument("--csv")
    r.add_argument("--json")
    r.set_defaults(fn=cmd_report)
    sub.add_parser("update-oui", help="descargar la base de fabricantes MAC").set_defaults(fn=cmd_update_oui)

    args = p.parse_args(argv)
    ensure_dirs()
    if not getattr(args, "fn", None):
        p.print_help()
        return 0
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
