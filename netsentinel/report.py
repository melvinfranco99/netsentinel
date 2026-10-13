"""Exportación del resultado: CSV y un informe HTML autocontenido (imprimible a PDF)."""

import csv
import html
import io
import math
import time

from . import __version__
from .classify import TYPES
from .knowledge import SEV_LABEL, SEV_ORDER

SEV_COLOR = {"critical": "#d03b3b", "high": "#ec835a", "medium": "#fab219", "low": "#2a78d6", "info": "#898781"}


def to_csv(r: dict) -> str:
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(["IP", "MAC", "Fabricante", "Nombre", "Tipo", "Sistema", "Puertos abiertos",
                "Riesgo", "Severidad", "Hallazgo", "Puerto", "Evidencia", "Solución"])
    for h in r["hosts"]:
        base = [h["ip"], h.get("mac", ""), h.get("vendor", ""), h.get("alias") or h.get("hostname", ""),
                TYPES.get(h.get("type", ""), ""), h.get("os", ""),
                " ".join(str(s["port"]) for s in h.get("services", [])), h.get("risk", 0)]
        fs = h.get("findings") or [None]
        for f in fs:
            if f:
                w.writerow(base + [SEV_LABEL[f["severity"]], f["title"], f.get("port") or "",
                                   f.get("evidence", ""), " | ".join(f.get("fix", []))])
            else:
                w.writerow(base + ["", "", "", "", ""])
    return out.getvalue()


def _e(x) -> str:
    return html.escape(str(x if x is not None else ""))


def _donut(counts: dict) -> str:
    total = sum(counts.get(s, 0) for s in ("critical", "high", "medium", "low"))
    if not total:
        return '<svg viewBox="0 0 120 120" width="120" height="120"><circle cx="60" cy="60" r="46" fill="none" stroke="#0ca30c" stroke-width="16"/><text x="60" y="66" text-anchor="middle" font-size="18" font-weight="700" fill="#0b0b0b">0</text></svg>'
    parts, a0 = [], -math.pi / 2
    for s in ("critical", "high", "medium", "low"):
        n = counts.get(s, 0)
        if not n:
            continue
        a1 = a0 + 2 * math.pi * n / total
        gap = 0.03 if n != total else 0
        x0, y0 = 60 + 46 * math.cos(a0 + gap), 60 + 46 * math.sin(a0 + gap)
        x1, y1 = 60 + 46 * math.cos(a1 - gap), 60 + 46 * math.sin(a1 - gap)
        large = 1 if (a1 - a0) > math.pi else 0
        if n == total:
            parts.append(f'<circle cx="60" cy="60" r="46" fill="none" stroke="{SEV_COLOR[s]}" stroke-width="16"/>')
        else:
            parts.append(f'<path d="M{x0:.2f},{y0:.2f} A46,46 0 {large} 1 {x1:.2f},{y1:.2f}" fill="none" '
                         f'stroke="{SEV_COLOR[s]}" stroke-width="16"/>')
        a0 = a1
    return (f'<svg viewBox="0 0 120 120" width="120" height="120">{"".join(parts)}'
            f'<text x="60" y="66" text-anchor="middle" font-size="20" font-weight="700" fill="#0b0b0b">{total}</text></svg>')


def to_html(r: dict) -> str:
    sc = r["score"]
    when = time.strftime("%d/%m/%Y %H:%M", time.localtime(r["started"]))
    net = r.get("network", {})
    # Agrupa hallazgos por tipo
    groups: dict = {}
    for h in r["hosts"]:
        for f in h.get("findings", []):
            g = groups.setdefault((f["fid"], f["title"]), {"f": f, "hosts": []})
            g["hosts"].append((h, f))
    for f in r.get("network_findings", []):
        groups.setdefault((f["fid"], f["title"]), {"f": f, "hosts": []})
    ordered = sorted(groups.values(), key=lambda g: (-SEV_ORDER[g["f"]["severity"]], -len(g["hosts"])))
    grade_color = {"A": "#0ca30c", "B": "#0ca30c", "C": "#fab219", "D": "#ec835a", "F": "#d03b3b"}[sc["grade"]]

    rows = []
    for h in r["hosts"]:
        worst = max((SEV_ORDER[f["severity"]] for f in h.get("findings", [])), default=-1)
        wsev = next((k for k, v in SEV_ORDER.items() if v == worst), None)
        badge = f'<span class="b" style="background:{SEV_COLOR[wsev]}">{SEV_LABEL[wsev]}</span>' if wsev and wsev != "info" else '<span class="ok">OK</span>'
        rows.append(f"<tr><td class='mono'>{_e(h['ip'])}</td><td>{_e(h.get('alias') or h.get('hostname') or '—')}</td>"
                    f"<td>{_e(TYPES.get(h.get('type'), ''))}</td><td>{_e(h.get('vendor') or '—')}</td>"
                    f"<td class='mono'>{_e(h.get('mac') or '')}</td>"
                    f"<td class='mono'>{_e(', '.join(str(s['port']) for s in h.get('services', [])) or '—')}</td>"
                    f"<td>{badge}</td></tr>")
    cards = []
    for g in ordered:
        f = g["f"]
        if f["severity"] == "info" and not g["hosts"]:
            continue
        affected = ", ".join(f"{_e(h['ip'])}" + (f":{fx['port']}" if fx.get("port") else "") for h, fx in g["hosts"]) or "Red Wi-Fi"
        fixes = "".join(f"<li>{_e(x)}</li>" for x in f.get("fix", []))
        refs = " · ".join(_e(x) for x in f.get("refs", [])[:4])
        cards.append(f"""<div class="card sev-{f['severity']}">
<div class="ch"><span class="b" style="background:{SEV_COLOR[f['severity']]}">{SEV_LABEL[f['severity']]}</span>
<h3>{_e(f['title'])}</h3><span class="cat">{_e(f['category'])}</span></div>
<p>{_e(f['description'])}</p><p><b>Impacto:</b> {_e(f['impact'])}</p>
<p><b>Afectados:</b> <span class="mono">{affected}</span></p>
<div class="fix"><b>Cómo solucionarlo</b><ol>{fixes}</ol></div>
{f'<p class="refs">Referencias: {refs}</p>' if refs else ''}</div>""")
    legend = "".join(f'<li><i style="background:{SEV_COLOR[s]}"></i>{SEV_LABEL[s]}: <b>{sc["counts"].get(s, 0)}</b></li>'
                     for s in ("critical", "high", "medium", "low"))
    return f"""<!doctype html><html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Informe NetSentinel · {_e(r['target'])}</title>
<style>
:root{{--ink:#0b0b0b;--ink2:#52514e;--mut:#898781;--line:#e1e0d9;--bg:#f9f9f7;--card:#fff}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--ink);font:14px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}}
.wrap{{max-width:1040px;margin:0 auto;padding:32px 20px}}h1{{margin:0;font-size:26px}}h2{{font-size:18px;margin:32px 0 12px}}
.sub{{color:var(--ink2)}}.mono{{font-family:ui-monospace,"JetBrains Mono",monospace;font-size:12.5px}}
.top{{display:flex;gap:16px;flex-wrap:wrap;margin-top:20px}}.tile{{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px 18px;flex:1;min-width:150px}}
.tile .v{{font-size:28px;font-weight:700}}.tile .l{{color:var(--ink2);font-size:12.5px}}
.grade{{font-size:44px;font-weight:800;color:{grade_color}}}
.sev{{display:flex;align-items:center;gap:18px}}.sev ul{{list-style:none;padding:0;margin:0}}.sev li{{display:flex;align-items:center;gap:8px}}.sev i{{width:10px;height:10px;border-radius:3px;display:inline-block}}
table{{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);border-radius:12px;overflow:hidden}}
th,td{{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top}}th{{font-size:12px;color:var(--ink2);background:#f3f2ee}}
.b{{color:#fff;border-radius:999px;padding:1px 9px;font-size:11.5px;font-weight:600;white-space:nowrap}}.sev-medium .b,.b[style*="fab219"]{{color:#0b0b0b}}
.ok{{color:#006300;font-weight:600}}
.card{{background:var(--card);border:1px solid var(--line);border-left:4px solid var(--mut);border-radius:10px;padding:14px 16px;margin-bottom:12px;break-inside:avoid}}
.sev-critical{{border-left-color:#d03b3b}}.sev-high{{border-left-color:#ec835a}}.sev-medium{{border-left-color:#fab219}}.sev-low{{border-left-color:#2a78d6}}
.ch{{display:flex;align-items:center;gap:10px;flex-wrap:wrap}}.ch h3{{margin:0;font-size:15.5px}}.cat{{color:var(--mut);font-size:12px;margin-left:auto}}
.card p{{margin:6px 0}}.fix{{background:#f3f7fd;border-radius:8px;padding:8px 12px;margin-top:8px}}.fix ol{{margin:4px 0 0;padding-left:20px}}
.refs{{color:var(--mut);font-size:12px}}footer{{color:var(--mut);font-size:12px;margin-top:40px}}
@media print{{body{{background:#fff}}.wrap{{padding:0}}.tile,.card,table{{border-color:#ccc}}}}
</style></head><body><div class="wrap">
<h1>Informe de seguridad de red</h1>
<div class="sub">Objetivo <b class="mono">{_e(r['target'])}</b> · {when} · perfil {_e(r.get('profile_label', ''))} · duración {r.get('duration', 0)} s
{(' · Wi-Fi «' + _e(net['wifi']['ssid']) + '»') if net.get('wifi') else ''}</div>
<div class="top">
<div class="tile"><div class="l">Nota de seguridad</div><div class="grade">{sc['grade']}</div><div class="l">{sc['score']}/100</div></div>
<div class="tile"><div class="l">Dispositivos</div><div class="v">{len(r['hosts'])}</div><div class="l">{r['summary'].get('new_devices', 0)} nuevos</div></div>
<div class="tile"><div class="l">Puertos abiertos</div><div class="v">{r['summary']['open_ports']}</div><div class="l">{r.get('ports_scanned', 0)} puertos analizados por equipo</div></div>
<div class="tile sev">{_donut(sc['counts'])}<ul>{legend}</ul></div>
</div>
<h2>Dispositivos</h2>
<table><thead><tr><th>IP</th><th>Nombre</th><th>Tipo</th><th>Fabricante</th><th>MAC</th><th>Puertos</th><th>Riesgo</th></tr></thead>
<tbody>{''.join(rows)}</tbody></table>
<h2>Hallazgos y cómo solucionarlos</h2>
{''.join(cards) or '<p>No se han encontrado problemas. ¡Buen trabajo!</p>'}
<footer>Generado por NetSentinel {__version__}. Este informe refleja el estado de la red en el momento del análisis; las comprobaciones no intrusivas no garantizan la ausencia de otras vulnerabilidades.</footer>
</div></body></html>"""
