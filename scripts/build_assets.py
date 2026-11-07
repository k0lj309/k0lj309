#!/usr/bin/env python3
"""Asset generator for the k0lj309 profile README.

    python3 scripts/build_assets.py

Zero dependencies. The SVGs are self-contained (no scripts, no external fonts
or images) and always use the dark design on a solid background.
With prefers-reduced-motion the header shows its finished state.

activity.svg is drawn from live GitHub data and needs a token from
$STATS_TOKEN / $GITHUB_TOKEN / $GH_TOKEN or a logged-in `gh` CLI; without one
it is left as it is. .github/workflows/refresh-stats.yml redraws it daily.
"""
from __future__ import annotations

import datetime as dt
import html
import json
import os
import pathlib
import subprocess
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT = ROOT / 'assets'
LOGIN = 'k0lj309'
W = 900

SANS = "-apple-system, BlinkMacSystemFont, 'Segoe UI', 'Noto Sans', Helvetica, Arial, sans-serif"

# GitHub's own text/border colours, so the graphics sit in the page like text
MONO = "ui-monospace, SFMono-Regular, Menlo, Consolas, 'Liberation Mono', monospace"

LIGHT = {'fg': '#1f2328', 'mu': '#59636e', 'ln': '#d1d9e0', 'bg': '#ffffff', 'rd': '#cf222e', 'gr': '#1a7f37',
         'heat': ['#eff1f3', '#d0d7de', '#8c959f', '#57606a', '#1f2328']}
DARK = {'fg': '#f0f6fc', 'mu': '#9198a1', 'ln': '#3d444d', 'bg': '#0d1117', 'rd': '#f85149', 'gr': '#3fb950',
        'heat': ['#1b1f24', '#30363d', '#5d656e', '#9198a1', '#f0f6fc']}


def theme_css(t) -> str:
    rules = [f".fg{{fill:{t['fg']}}}", f".mu{{fill:{t['mu']}}}", f".ln{{stroke:{t['ln']}}}",
             f".sf{{stroke:{t['fg']}}}", f".sm{{stroke:{t['mu']}}}", f".bg{{fill:{t['bg']}}}",
             f".rd{{fill:{t['rd']}}}", f".gr{{fill:{t['gr']}}}"]
    rules += [f'.h{i}{{fill:{c}}}' for i, c in enumerate(t['heat'])]
    return ''.join(rules)


# reduced motion: no moving parts, show the finished first run (.r1 = second run only)
# always the dark design, on a solid background so it also reads on GitHub's light theme
BASE_CSS = (theme_css(DARK)
            + '.mono{font-family:' + MONO + '}'
            + '@media (prefers-reduced-motion: reduce){*{animation:none!important}.mv,.r1,.ring{display:none}}')


def esc(s) -> str:
    return html.escape(str(s), quote=True)


PAD = 20


def svg(h, body, css='', label='') -> str:
    H = h + 2 * PAD
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}" '
        f'role="img" aria-label="{esc(label)}"><title>{esc(label)}</title>'
        f'<style>{BASE_CSS}{css}</style><rect width="{W}" height="{H}" rx="12" class="bg"/>'
        f'<g font-family="{esc(SANS)}" transform="translate({PAD} {PAD})">{body}</g></svg>\n'
    )


# ================================================================= header
def window(name, period, on, off, fade=.12) -> str:
    """CSS class `name`: visible from `on` to `off` seconds in every `period`-second cycle."""
    p = lambda t: f'{100 * t / period:.2f}%'
    return (f'@keyframes {name}{{0%,{p(on)}{{opacity:0}}{p(on + fade)},{p(off)}{{opacity:1}}'
            f'{p(min(off + .3, period))},100%{{opacity:0}}}}.{name}{{animation:{name} {period}s linear infinite}}')


def dot(d, period, t0, t1, cls='fg') -> str:
    """A dot travelling along path d between t0 and t1 of every period."""
    a, z, e = t0 / period, t1 / period, .002
    return (f'<g class="mv" opacity="0"><circle r="2.6" class="{cls}"/>'
            f'<animateMotion dur="{period}s" repeatCount="indefinite" path="{d}" calcMode="spline" '
            f'keyPoints="0;0;1;1" keyTimes="0;{a:.4f};{z:.4f};1" keySplines="0 0 1 1;.4 0 .2 1;0 0 1 1"/>'
            f'<animate attributeName="opacity" dur="{period}s" repeatCount="indefinite" values="0;0;1;1;0;0" '
            f'keyTimes="0;{a:.4f};{a + e:.4f};{z - e:.4f};{z:.4f};1"/></g>')


def curve(x1, y1, x2, y2) -> str:
    m = (x1 + x2) / 2
    return f'M{x1} {y1} C{m} {y1} {m} {y2} {x2} {y2}'


def build_header() -> str:
    """Name block plus an alert-triage workflow.

    Two events take turns (R seconds each, full cycle T = 2R): a malicious one
    that ends in "block + notify" and a benign one that ends in "close". Nodes
    shared by both runs animate on the R cycle, run-specific parts on T.
    """
    H, R = 318, 6.0
    T = 2 * R
    cy, r = 206, 5
    N = {  # name: (x, y, label, label position)
        'alert': (22, cy, 'alert', 'below'),
        'enrich': (142, cy, 'enrich', 'below'),
        'geoip': (282, cy - 46, 'geoip', 'below'),
        'rep': (282, cy, 'reputation', 'below'),
        'whois': (282, cy + 46, 'whois', 'below'),
        'score': (422, cy, 'score', 'below'),
        'verdict': (542, cy, 'verdict', 'below'),
        'block': (682, cy - 30, 'block + notify', 'right'),
        'close': (682, cy + 30, 'close', 'right'),
    }
    # (seconds into a run) when each node lights up; it stays lit until `off`
    lit = {'alert': .3, 'enrich': 1.0, 'geoip': 1.8, 'rep': 1.8, 'whois': 1.8,
           'score': 2.6, 'verdict': 3.2, 'block': 3.9, 'close': 3.9}
    off = R - .5
    edges = [('alert', 'enrich', .35, 1.0), ('enrich', 'geoip', 1.05, 1.8), ('enrich', 'rep', 1.05, 1.8),
             ('enrich', 'whois', 1.05, 1.8), ('geoip', 'score', 1.85, 2.6), ('rep', 'score', 1.85, 2.6),
             ('whois', 'score', 1.85, 2.6), ('score', 'verdict', 2.65, 3.2)]

    css = []
    b = [f'<text x="2" y="52" class="fg" font-size="44" font-weight="600" letter-spacing="-1">Sm0k</text>',
         f'<text x="4" y="86" class="mu" font-size="17">Cybersecurity &amp; Automation</text>',
         f'<text x="4" y="110" class="mu" font-size="14" opacity=".75">always learning something new</text>']

    def path(a, z):
        (x1, y1, *_), (x2, y2, *_) = N[a], N[z]
        return curve(x1 + r + 3, y1, x2 - r - 3, y2)

    # edges
    for a, z, *_ in edges + [('verdict', 'block', 0, 0), ('verdict', 'close', 0, 0)]:
        b.append(f'<path d="{path(a, z)}" fill="none" class="ln" stroke-width="1.5"/>')
    # nodes
    for k, (x, y, label, pos) in N.items():
        diamond = k == 'verdict'
        shape = (f'<path d="M{x} {y - 6.5} L{x + 6.5} {y} L{x} {y + 6.5} L{x - 6.5} {y} Z"' if diamond
                 else f'<circle cx="{x}" cy="{y}" r="{r}"')
        b.append(f'{shape} class="bg sm" stroke-width="1.5"/>')
        if k in ('block', 'close'):
            col, run = ('rd', 0) if k == 'block' else ('gr', 1)
            t0 = run * R + lit[k]
            css.append(window(f'n_{k}', T, t0, run * R + off))
            b.append(f'{shape} class="{col} n_{k}{" r1" if run else ""}"/>')
        else:
            css.append(window(f'n_{k}', R, lit[k], off))
            b.append(f'{shape} class="fg n_{k}"/>')
        if pos == 'below':
            b.append(f'<text x="{x}" y="{y + 22}" text-anchor="middle" class="mu" font-size="12">{label}</text>')
        else:
            b.append(f'<text x="{x + 14}" y="{y + 4.5}" class="mu" font-size="12">{label}</text>')
    # incoming-alert ring
    ax, ay = N['alert'][:2]
    b.append(f'<circle cx="{ax}" cy="{ay}" r="{r}" fill="none" class="sf ring" stroke-width="1"/>')
    css.append('.ring{transform-box:fill-box;transform-origin:center;opacity:0;animation:ring 6s ease-out infinite}'
               f'@keyframes ring{{0%,{100 * .2 / R:.2f}%{{transform:scale(1);opacity:0}}'
               f'{100 * .3 / R:.2f}%{{opacity:.9}}{100 * 1.4 / R:.2f}%,100%{{transform:scale(3.4);opacity:0}}}}')
    # packets
    for a, z, t0, t1 in edges:
        b.append(dot(path(a, z), R, t0, t1))
    b.append(dot(path('verdict', 'block'), T, 3.25, 3.9, 'rd'))
    b.append(dot(path('verdict', 'close'), T, R + 3.25, R + 3.9, 'gr'))

    # event log (documentation-range IPs, RFC 5737)
    ly = H - 14
    runs = [('203.0.113.42', 'risk 92/100', 'blocked', 'rd'), ('198.51.100.7', 'risk 4/100', 'closed', 'gr')]
    b.append(f'<text x="4" y="{ly}" class="mono mu" font-size="12.5">›</text>')
    for i, (ip, risk, outcome, col) in enumerate(runs):
        s, r1 = i * R, ' r1' if i else ''
        for name, x, t0, text, cls in ((f'l{i}a', 22, .3, ip, 'fg'), (f'l{i}b', 150, 2.6, risk, 'mu'),
                                       (f'l{i}c', 266, 3.9, f'→ {outcome}', col)):
            css.append(window(name, T, s + t0, s + off))
            b.append(f'<text x="{x}" y="{ly}" class="mono {cls} {name}{r1}" font-size="12.5">{esc(text)}</text>')
    return svg(H, ''.join(b), ''.join(css),
               'Sm0k — Cybersecurity & Automation. Always learning something new. An animated alert-triage '
               'workflow: an alert is enriched in parallel (geoip, reputation, whois), scored, and a verdict '
               'either blocks it and notifies, or closes it.')


# ================================================================= live activity
def gh_token():
    for k in ('STATS_TOKEN', 'GITHUB_TOKEN', 'GH_TOKEN'):
        if os.environ.get(k):
            return os.environ[k]
    try:
        tok = subprocess.run(['gh', 'auth', 'token'], capture_output=True, text=True, check=True).stdout.strip()
        return tok or None
    except Exception:
        return None


QUERY = """query($login:String!){user(login:$login){
  contributionsCollection{contributionCalendar{totalContributions
    weeks{contributionDays{date contributionCount weekday}}}}
  repositories(first:100,ownerAffiliations:OWNER,isFork:false){
    nodes{languages(first:12,orderBy:{field:SIZE,direction:DESC}){edges{size node{name}}}}}
}}"""

SKIP_LANGS = {'HTML', 'CSS', 'SCSS', 'MDX', 'Dockerfile', 'Makefile', 'Jupyter Notebook', 'Procfile'}


def fetch(token):
    req = urllib.request.Request(
        'https://api.github.com/graphql',
        data=json.dumps({'query': QUERY, 'variables': {'login': LOGIN}}).encode(),
        headers={'Authorization': f'bearer {token}', 'User-Agent': 'profile-readme-builder',
                 'Content-Type': 'application/json'})
    with urllib.request.urlopen(req, timeout=30) as r:
        data = json.load(r)
    if data.get('errors'):
        raise RuntimeError(data['errors'])
    return data['data']['user']


def summarize(u):
    cal = u['contributionsCollection']['contributionCalendar']
    weeks = [w['contributionDays'] for w in cal['weeks']]
    counts = [d['contributionCount'] for w in weeks for d in w]
    longest = run = 0
    for c in counts:
        run = run + 1 if c else 0
        longest = max(longest, run)
    sizes = {}
    for r in u['repositories']['nodes']:
        for e in r['languages']['edges']:
            n = e['node']['name']
            if n not in SKIP_LANGS:
                sizes[n] = sizes.get(n, 0) + e['size']
    top = max(sizes, key=sizes.get) if sizes else None
    return {'weeks': weeks, 'total': cal['totalContributions'], 'longest': longest, 'top': top}


def build_activity(s) -> str:
    H = 144
    weeks = s['weeks']
    cell, gap = 10, 3
    step = cell + gap
    x0, y0 = 4, 50
    nz = sorted(d['contributionCount'] for w in weeks for d in w if d['contributionCount'])
    # quartiles of the non-zero days (like GitHub), so one huge day doesn't flatten the rest
    qs = [nz[min(len(nz) - 1, int(len(nz) * q))] for q in (.25, .5, .75)] if nz else [1, 1, 1]

    def level(c):
        return 0 if c == 0 else 1 + sum(c > q for q in qs)

    parts = [f'<tspan class="fg">{s["total"]:,}</tspan> contributions in the last year',
             f'longest streak <tspan class="fg">{s["longest"]}</tspan> days']
    if s['top']:
        parts.append(f'mostly <tspan class="fg">{esc(s["top"])}</tspan>')
    b = [f'<text x="{x0}" y="16" class="mu" font-size="14">{"   ·   ".join(parts)}</text>']
    last_month = None
    for wi, w in enumerate(weeks):
        day0 = dt.date.fromisoformat(w[0]['date'])
        if day0.month != last_month and wi < len(weeks) - 2:
            if last_month is not None or day0.day <= 7:
                b.append(f'<text x="{x0 + wi * step}" y="{y0 - 9}" class="mu" font-size="10.5">{day0.strftime("%b")}</text>')
            last_month = day0.month
        for d in w:
            b.append(f'<rect x="{x0 + wi * step}" y="{y0 + d["weekday"] * step}" width="{cell}" height="{cell}" '
                     f'rx="2" class="h{level(d["contributionCount"])}"/>')
    return svg(H, ''.join(b), '',
               f"{s['total']} contributions in the last year, longest streak {s['longest']} days"
               + (f", mostly {s['top']}" if s['top'] else '') + '. Contribution heatmap.')


# ================================================================= main
def write(name, content):
    p = OUT / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding='utf-8')
    print(f'wrote {p.relative_to(ROOT)} ({len(content) / 1024:.1f} KB)')


def main():
    write('header.svg', build_header())
    token = gh_token()
    if not token:
        print('no GitHub token found: leaving activity.svg untouched')
        return
    write('activity.svg', build_activity(summarize(fetch(token))))


if __name__ == '__main__':
    main()
