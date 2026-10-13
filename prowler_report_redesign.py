#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
prowler_report_redesign.py - offline redesign of Prowler HTML reports.

Takes the HTML report that Prowler writes (prowler-output-*.html) and produces a
standalone, offline, redesigned HTML report: dashboard, Dark/Light mode, search,
filter panes, sorting, paging, expandable details and CSV export.

No internet access and no third-party packages are needed (Python 3.7+ standard library).
The cell HTML of every finding is copied byte-for-byte from the source; the tool
verifies that after building and refuses to write the file if anything differs.

Usage:
    python prowler_report_redesign.py <report.html> [more.html ...] [-o OUTPUT] [--title TEXT]

Examples:
    python prowler_report_redesign.py prowler-output-myproject-20260101000000.html
    python prowler_report_redesign.py report.html -o PROLWER_Cloud_Report_Redesigned.html
    python prowler_report_redesign.py C:\\reports\\*.html -o C:\\reports\\redesigned
"""
import argparse
import datetime
import glob
import html
import json
import os
import re
import sys

__version__ = "1.0.0"

DEFAULT_PANE_COLS = [0, 1, 2, 3, 5, 7]   # Prowler's SearchPanes columnDefs targets
DEFAULT_ORDER = [[5, "asc"]]              # Prowler's data-order
DEFAULT_PAGE_LENGTH = 100                 # Prowler's data-page-length


class ReportError(Exception):
    pass


# --------------------------------------------------------------------------- helpers

def strip_tags(s):
    s = re.sub(r"<wbr\s*/?>", "", s, flags=re.I)
    s = re.sub(r"<br\s*/?>", " ", s, flags=re.I)
    s = re.sub(r"<[^>]*>", " ", s)
    return re.sub(r"\s+", " ", html.unescape(s)).strip()


def read_text(path):
    with open(path, "rb") as f:
        raw = f.read()
    if raw.startswith(b"\xef\xbb\xbf"):
        raw = raw[3:]
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        print("  warning: file is not valid UTF-8, undecodable bytes were replaced", file=sys.stderr)
        return raw.decode("utf-8", errors="replace")


# --------------------------------------------------------------------------- parsing

def parse_report(src):
    m = re.search(r'<table\b[^>]*\bid=["\']findingsTable["\'][^>]*>', src, re.I)
    if not m:
        m = re.search(r"<table\b[^>]*>", src, re.I)
        if not m:
            raise ReportError("no <table> found - is this a Prowler HTML report?")
        print("  warning: table id 'findingsTable' not found, using the first table", file=sys.stderr)
    table_tag = m.group(0)
    pre = src[:m.start()]
    rest = src[m.end():]

    thead = re.search(r"<thead\b[^>]*>(.*?)</thead>", rest, re.S | re.I)
    if not thead:
        raise ReportError("table has no <thead>")
    cols = [strip_tags(x) for x in re.findall(r"<th\b[^>]*>(.*?)</th>", thead.group(1), re.S | re.I)]
    if not cols:
        raise ReportError("no column headers found")

    tb = re.search(r"<tbody\b[^>]*>", rest, re.I)
    if not tb:
        raise ReportError("table has no <tbody>")
    tb_end = rest.find("</tbody>", tb.end())
    if tb_end == -1:
        tb_end = rest.find("</table>", tb.end())
    tbody = rest[tb.end():tb_end]

    rows = []
    for rm in re.finditer(r"<tr\b([^>]*)>(.*?)</tr>", tbody, re.S | re.I):
        cm = re.search(r'class\s*=\s*["\']([^"\']*)["\']', rm.group(1))
        cells = re.findall(r"<td\b[^>]*>(.*?)</td>", rm.group(2), re.S | re.I)
        if len(cells) != len(cols):
            raise ReportError("row %d has %d cells but the table has %d columns" % (len(rows) + 1, len(cells), len(cols)))
        rows.append([cm.group(1) if cm else ""] + cells)
    tr_count = len(re.findall(r"<tr\b", tbody, re.I))
    if tr_count != len(rows):
        raise ReportError("found %d <tr> tags but could parse only %d rows" % (tr_count, len(rows)))

    # header cards (Report Information, <Provider> Assessment Summary, Credentials, Assessment Overview ...)
    cards = []
    for cmatch in re.finditer(r'<div class="card-header">\s*(.*?)\s*</div>\s*<ul\b[^>]*>(.*?)</ul>', pre, re.S | re.I):
        items = []
        for li in re.findall(r"<li\b[^>]*>(.*?)</li>", cmatch.group(2), re.S | re.I):
            li = re.sub(r"</?div\b[^>]*>", "", li, flags=re.I).strip()
            bm = re.match(r"\s*<b>(.*?)</b>(.*)$", li, re.S | re.I)
            if bm:
                key = strip_tags(bm.group(1)).rstrip(":").strip()
                items.append([key, bm.group(2).strip()])
            else:
                items.append(["", li])
        cards.append({"title": strip_tags(cmatch.group(1)), "items": items})

    logo = None
    lm = re.search(r'<a\s+href="([^"]+)"\s*>\s*<img\b([^>]*)>', pre, re.S | re.I)
    if lm:
        sm = re.search(r'src\s*=\s*["\']?([^"\'\s>]+)', lm.group(2))
        logo = {"href": lm.group(1), "src": sm.group(1) if sm else ""}

    cfg = {"paneCols": DEFAULT_PANE_COLS, "order": DEFAULT_ORDER, "pageLength": DEFAULT_PAGE_LENGTH}
    om = re.search(r"data-order\s*=\s*'([^']*)'", table_tag) or re.search(r'data-order\s*=\s*"([^"]*)"', table_tag)
    if om:
        try:
            cfg["order"] = json.loads(html.unescape(om.group(1)))
        except ValueError:
            pass
    pm = re.search(r"data-page-length\s*=\s*['\"]?(\d+)", table_tag)
    if pm:
        cfg["pageLength"] = int(pm.group(1))
    tm = re.search(r"targets\s*:\s*\[([\d,\s]+)\]", src[m.end():])
    if tm:
        cfg["paneCols"] = [int(x) for x in tm.group(1).split(",") if x.strip()]

    return {"cols": cols, "rows": rows, "cards": cards, "logo": logo, "config": cfg}


# --------------------------------------------------------------------------- building

def card_value(cards, key):
    for c in cards:
        for k, v in c["items"]:
            if k.lower() == key.lower():
                return v
    return None


def build_info_cards(cards, logo):
    out = []
    for i, c in enumerate(cards):
        h = ['      <div class="card info-card">', "        <h3>%s</h3>" % html.escape(c["title"]), "        <dl>"]
        for k, v in c["items"]:
            empty = not strip_tags(v)
            h.append('          <div class="kv"><dt>%s</dt><dd%s>%s</dd></div>'
                     % (html.escape(k), ' class="empty"' if empty else "", "(empty)" if empty else v))
        h.append("        </dl>")
        if logo and (c["title"].lower() == "report information" or (i == 0 and not any(x["title"].lower() == "report information" for x in cards))):
            label = re.sub(r"^https?://", "", logo["href"]).rstrip("/")
            img = ('<img src="%s" alt="prowler-logo" onerror="this.remove()" />' % html.escape(logo["src"], quote=True)) if logo["src"] else ""
            h.append('        <a class="logo-link" href="%s">%s<span>%s</span></a>' % (html.escape(logo["href"], quote=True), img, html.escape(label)))
        h.append("      </div>")
        out.append("\n".join(h))
    return "\n".join(out)


def encode_rows(cols, rows):
    index, strings, encoded = {}, [], []
    for row in rows:
        enc = []
        for s in row:
            i = index.get(s)
            if i is None:
                i = index[s] = len(strings)
                strings.append(s)
            enc.append(i)
        encoded.append(enc)
    return {"cols": cols, "s": strings, "r": encoded}


def json_for_script(obj):
    s = json.dumps(obj, ensure_ascii=False, separators=(",", ":"))
    # keep the JSON from terminating the <script> element early
    return s.replace("</", "<\\/").replace("<!--", "\\u003c!--")


def build(parsed, title):
    cards = parsed["cards"]
    summary = next((c for c in cards if "assessment summary" in c["title"].lower()), None)
    subtitle_parts, file_tag = [], "report"
    if summary and summary["items"]:
        k, v = summary["items"][0]
        subtitle_parts.append("%s: <b>%s</b>" % (html.escape(k), html.escape(strip_tags(v))))
        file_tag = re.sub(r"[^A-Za-z0-9._-]+", "_", strip_tags(v))[:60] or "report"
    date_raw = strip_tags(card_value(cards, "Date") or "")
    if date_raw:
        try:
            d = datetime.datetime.fromisoformat(date_raw)
            human = d.strftime("%d %b %Y, %H:%M") + (" UTC" if d.utcoffset() == datetime.timedelta(0) else "")
        except ValueError:
            human = date_raw
        subtitle_parts.append('<time datetime="%s">%s</time>' % (html.escape(date_raw, quote=True), html.escape(human)))

    cfg = dict(parsed["config"])
    cfg["fileTag"] = file_tag
    data = encode_rows(parsed["cols"], parsed["rows"])
    values = {
        "PAGE_TITLE": html.escape(title),
        "TITLE": html.escape(title),
        "SUBTITLE": ", ".join(subtitle_parts),
        "INFO_CARDS": build_info_cards(cards, parsed["logo"]),
        "DATA": json_for_script(data),
        "CONFIG": json_for_script(cfg),
    }
    # single pass, so values are never re-scanned for placeholders
    return re.sub(r"\{\{([A-Z_]+)\}\}", lambda mm: values[mm.group(1)], TEMPLATE)


def verify(output, parsed):
    m = re.search(r'<script type="application/json" id="report-data">(.*?)</script>', output, re.S)
    if not m:
        raise ReportError("verification failed: data block missing in output")
    data = json.loads(m.group(1))
    decoded = [[data["s"][i] for i in r] for r in data["r"]]
    if decoded != parsed["rows"] or data["cols"] != parsed["cols"]:
        raise ReportError("verification failed: decoded rows differ from the source")


def consistency_warnings(parsed):
    warns = []
    cols = [c.lower() for c in parsed["cols"]]
    n = len(parsed["rows"])
    total = card_value(parsed["cards"], "Total Findings")
    if total and strip_tags(total).isdigit() and int(strip_tags(total)) != n:
        warns.append("header says Total Findings = %s but the table has %d rows" % (strip_tags(total), n))
    if "status" in cols:
        ci = cols.index("status") + 1
        counts = {}
        for r in parsed["rows"]:
            st = strip_tags(r[ci]).upper()
            counts[st] = counts.get(st, 0) + 1
        for key, st in (("Passed", "PASS"), ("Failed", "FAIL")):
            v = card_value(parsed["cards"], key)
            if v and strip_tags(v).isdigit() and int(strip_tags(v)) != counts.get(st, 0):
                warns.append("header says %s = %s but the table has %d %s rows" % (key, strip_tags(v), counts.get(st, 0), st))
        others = {k: v for k, v in counts.items() if k not in ("PASS", "FAIL")}
        if others:
            warns.append("statuses other than PASS/FAIL present: %s" % ", ".join("%s=%d" % kv for kv in sorted(others.items())))
    missing = [c for c in ("Status", "Severity", "Service Name", "Check ID", "Check Title", "Resource ID") if c.lower() not in cols]
    if missing:
        warns.append("expected columns not found (related widgets are hidden): %s" % ", ".join(missing))
    return warns


# --------------------------------------------------------------------------- CLI

def resolve_inputs(patterns):
    files = []
    for p in patterns:
        hits = glob.glob(p) if any(ch in p for ch in "*?[") else [p]
        if not hits:
            print("error: no file matches %s" % p, file=sys.stderr)
        for h in hits:
            if os.path.isdir(h):
                files.extend(sorted(glob.glob(os.path.join(h, "*.html"))))
            else:
                files.append(h)
    return files


def output_path(inp, out_arg, multi):
    stem = os.path.splitext(os.path.basename(inp))[0]
    default_name = stem + "_redesigned.html"
    if not out_arg:
        return os.path.join(os.path.dirname(os.path.abspath(inp)), default_name)
    if multi or os.path.isdir(out_arg) or out_arg.endswith(("/", "\\")):
        os.makedirs(out_arg, exist_ok=True)
        return os.path.join(out_arg, default_name)
    return out_arg


def main(argv=None):
    ap = argparse.ArgumentParser(description="Offline redesign of Prowler HTML reports.")
    ap.add_argument("inputs", nargs="+", help="Prowler HTML report file(s), folder(s) or wildcard(s)")
    ap.add_argument("-o", "--output", help="output file (single input) or output folder")
    ap.add_argument("--title", default="Prowler Cloud Assessment Report", help="report title shown in the header")
    ap.add_argument("--version", action="version", version="%(prog)s " + __version__)
    args = ap.parse_args(argv)

    files = resolve_inputs(args.inputs)
    if not files:
        return 2
    multi = len(files) > 1
    failed = 0
    for f in files:
        print("%s" % f)
        try:
            if not os.path.isfile(f):
                raise ReportError("file not found")
            parsed = parse_report(read_text(f))
            out = build(parsed, args.title)
            verify(out, parsed)
            dest = output_path(f, args.output, multi)
            if os.path.abspath(dest) == os.path.abspath(f):
                raise ReportError("output path is the same as the input file")
            d = os.path.dirname(os.path.abspath(dest))
            if not os.path.isdir(d):
                os.makedirs(d)
            with open(dest, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(out)
            for w in consistency_warnings(parsed):
                print("  warning: " + w)
            print("  %d findings, %d columns, %.1f MB -> %.1f MB, verified" % (
                len(parsed["rows"]), len(parsed["cols"]), os.path.getsize(f) / 1048576.0, os.path.getsize(dest) / 1048576.0))
            print("  -> %s" % dest)
        except ReportError as e:
            failed += 1
            print("  error: %s" % e, file=sys.stderr)
        except (OSError, IOError) as e:
            failed += 1
            print("  error: %s" % e, file=sys.stderr)
    return 1 if failed else 0



# --------------------------------------------------------------------------- template

TEMPLATE = r"""<!DOCTYPE html>
<html lang="en" data-theme="light">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<meta name="color-scheme" content="light dark" />
<title>{{PAGE_TITLE}}</title>
<script>
/* Theme is applied before first paint to avoid a flash of the wrong theme. */
(function () {
  var t = null;
  try { t = window.localStorage.getItem('prowler-report-theme'); } catch (e) {}
  if (t !== 'light' && t !== 'dark') {
    t = (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) ? 'dark' : 'light';
  }
  document.documentElement.setAttribute('data-theme', t);
})();
</script>
<style>
:root {
  --gcp-blue: #4285F4;
  --gcp-red: #EA4335;
  --gcp-yellow: #FBBC04;
  --gcp-green: #34A853;
  --gcp-grey-900: #202124;
  --gcp-grey-700: #5F6368;
  --gcp-grey-500: #9AA0A6;
  --gcp-grey-300: #DADCE0;
  --gcp-grey-100: #F1F3F4;
  --gcp-white: #FFFFFF;

  --font: "Google Sans", "Product Sans", Roboto, "Segoe UI", Arial, sans-serif;
  --mono: "Roboto Mono", "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace;

  --r-sm: 8px;
  --r-md: 12px;
  --r-lg: 16px;
  --header-h: 64px;
}

html[data-theme="light"] {
  --bg: #F8F9FA;
  --surface: #FFFFFF;
  --surface-2: #F1F3F4;
  --surface-hover: #F1F5FE;
  --text: #202124;
  --text-2: #5F6368;
  --border: #DADCE0;
  --border-strong: #BDC1C6;
  --accent: #1A73E8;          /* Google Blue, darkened for AA text contrast */
  --accent-fill: #4285F4;
  --accent-soft: #E8F0FE;
  --focus: #1A73E8;
  --shadow: 0 1px 2px rgba(60,64,67,.15), 0 1px 3px 1px rgba(60,64,67,.08);

  --sev-critical: #D93025; --sev-critical-text: #A50E0E; --sev-critical-bg: #FCE8E6;
  --sev-high: #F29900;     --sev-high-text: #9A4A00;     --sev-high-bg: #FEF0DF;
  --sev-medium: #FBBC04;   --sev-medium-text: #7A5200;   --sev-medium-bg: #FEF7E0;
  --sev-low: #34A853;      --sev-low-text: #137333;      --sev-low-bg: #E6F4EA;

  --pass: #34A853; --pass-text: #137333; --pass-bg: #E6F4EA;
  --fail: #EA4335; --fail-text: #A50E0E; --fail-bg: #FCE8E6;
  --row-fail: #FFF7F6;
  --code-bg: #F1F3F4;
}

html[data-theme="dark"] {
  --bg: #1F1F1F;
  --surface: #292A2D;
  --surface-2: #2F3033;
  --surface-hover: #33363B;
  --text: #E8EAED;
  --text-2: #9AA0A6;
  --border: #3C4043;
  --border-strong: #5F6368;
  --accent: #8AB4F8;
  --accent-fill: #8AB4F8;
  --accent-soft: #2B3A55;
  --focus: #8AB4F8;
  --shadow: 0 1px 2px rgba(0,0,0,.3), 0 2px 6px 2px rgba(0,0,0,.15);

  --sev-critical: #F28B82; --sev-critical-text: #F6AEA9; --sev-critical-bg: #4A2624;
  --sev-high: #FCAD70;     --sev-high-text: #FDC69C;     --sev-high-bg: #4A3220;
  --sev-medium: #FDD663;   --sev-medium-text: #FDE293;   --sev-medium-bg: #47401E;
  --sev-low: #81C995;      --sev-low-text: #A8DAB5;      --sev-low-bg: #233A2A;

  --pass: #81C995; --pass-text: #A8DAB5; --pass-bg: #233A2A;
  --fail: #F28B82; --fail-text: #F6AEA9; --fail-bg: #4A2624;
  --row-fail: #2E2627;
  --code-bg: #202124;
}

*, *::before, *::after { box-sizing: border-box; }
[hidden] { display: none !important; }
html { scroll-behavior: smooth; }
@media (prefers-reduced-motion: reduce) { html { scroll-behavior: auto; } * { transition: none !important; } }
body {
  margin: 0;
  font-family: var(--font);
  font-size: 15px;
  line-height: 1.5;
  color: var(--text);
  background: var(--bg);
  -webkit-text-size-adjust: 100%;
}
a { color: var(--accent); }
a:hover { text-decoration: underline; }
code { font-family: var(--mono); font-size: .88em; background: var(--code-bg); border-radius: 4px; padding: .05em .35em; word-break: break-word; }
:focus-visible { outline: 2px solid var(--focus); outline-offset: 2px; border-radius: 4px; }
button { font: inherit; color: inherit; }
.sr-only { position: absolute; width: 1px; height: 1px; padding: 0; margin: -1px; overflow: hidden; clip: rect(0,0,0,0); white-space: nowrap; border: 0; }
.skip { position: absolute; left: 12px; top: -48px; background: var(--surface); color: var(--accent); padding: 8px 12px; border-radius: var(--r-sm); z-index: 100; box-shadow: var(--shadow); }
.skip:focus { top: 8px; }

/* ---------- Header ---------- */
.app-header {
  position: sticky; top: 0; z-index: 50;
  background: var(--surface);
  border-bottom: 1px solid var(--border);
}
.app-header__inner {
  max-width: 1600px; margin: 0 auto;
  display: flex; align-items: center; gap: 16px;
  min-height: var(--header-h); padding: 8px 16px;
  flex-wrap: wrap;
}
.brand { display: flex; align-items: center; gap: 12px; min-width: 0; flex: 0 1 auto; }
.brand svg { flex: none; }
.brand h1 { font-size: 18px; font-weight: 500; margin: 0; line-height: 1.25; }
.brand__meta { font-size: 13px; color: var(--text-2); }
.header-nav { display: flex; gap: 4px; margin-left: 8px; }
.header-nav a {
  text-decoration: none; color: var(--text-2); font-weight: 500; font-size: 14px;
  padding: 8px 12px; border-radius: 999px;
}
.header-nav a:hover { background: var(--surface-2); color: var(--text); text-decoration: none; }
.header-nav a[aria-current="true"] { background: var(--accent-soft); color: var(--accent); }
.header-right { margin-left: auto; display: flex; align-items: center; gap: 12px; }
.sev-chips { display: flex; gap: 6px; flex-wrap: wrap; }
.sev-chip {
  display: inline-flex; align-items: center; gap: 6px;
  border: 1px solid var(--border); background: var(--surface);
  border-radius: 999px; padding: 4px 10px 4px 8px; font-size: 13px; cursor: pointer;
}
.sev-chip:hover { background: var(--surface-2); }
.sev-chip b { font-weight: 600; font-variant-numeric: tabular-nums; }
.icon-btn {
  display: inline-flex; align-items: center; justify-content: center;
  width: 40px; height: 40px; border-radius: 50%;
  border: 1px solid var(--border); background: var(--surface); cursor: pointer; color: var(--text-2);
}
.icon-btn:hover { background: var(--surface-2); color: var(--text); }
.icon-btn:active { background: var(--accent-soft); }
html[data-theme="light"] .icon-sun-hide, html[data-theme="dark"] .icon-moon-hide { display: none; }
html[data-theme="light"] { color-scheme: light; }
html[data-theme="dark"] { color-scheme: dark; }

/* ---------- Layout ---------- */
main { max-width: 1600px; margin: 0 auto; padding: 24px 16px 48px; }
section { scroll-margin-top: calc(var(--header-h) + 16px); }
.section-head { display: flex; align-items: baseline; gap: 12px; flex-wrap: wrap; margin: 32px 0 16px; }
.section-head h2 { font-size: 22px; font-weight: 500; margin: 0; }
.section-head p { margin: 0; color: var(--text-2); font-size: 14px; }
.card { background: var(--surface); border: 1px solid var(--border); border-radius: var(--r-lg); }

/* ---------- Summary ---------- */
.summary-grid { display: grid; gap: 16px; grid-template-columns: 1fr; }
@media (min-width: 900px) { .summary-grid { grid-template-columns: minmax(280px, 340px) 1fr; } }

.overall { padding: 24px; display: flex; flex-direction: column; gap: 16px; }
.overall h3 { margin: 0; font-size: 16px; font-weight: 500; }
.donut-wrap { display: flex; align-items: center; gap: 24px; flex-wrap: wrap; }
.donut { position: relative; width: 148px; height: 148px; flex: none; }
.donut svg { transform: rotate(-90deg); }
.donut__center { position: absolute; inset: 0; display: flex; flex-direction: column; align-items: center; justify-content: center; text-align: center; }
.donut__center strong { font-size: 26px; font-weight: 500; font-variant-numeric: tabular-nums; }
.donut__center span { font-size: 12px; color: var(--text-2); }
.legend { list-style: none; margin: 0; padding: 0; display: grid; gap: 8px; font-size: 14px; }
.legend li { display: flex; align-items: center; gap: 8px; }
.legend b { font-variant-numeric: tabular-nums; font-weight: 600; margin-left: auto; padding-left: 16px; }
.swatch { width: 10px; height: 10px; border-radius: 3px; flex: none; }
.overall__note { font-size: 13px; color: var(--text-2); margin: 0; }

.sev-cards { display: grid; gap: 12px; grid-template-columns: repeat(auto-fit, minmax(190px, 1fr)); }
.sev-card {
  text-align: left; cursor: pointer;
  background: var(--surface); border: 1px solid var(--border);
  border-left: 6px solid var(--c); border-radius: var(--r-md);
  padding: 16px 16px 14px; display: flex; flex-direction: column; gap: 6px;
}
.sev-card:hover { background: var(--surface-hover); }
.sev-card:active { transform: translateY(1px); }
.sev-card__label { display: flex; align-items: center; gap: 8px; font-weight: 500; font-size: 15px; color: var(--ct); }
.sev-card__num { font-size: 34px; line-height: 1.1; font-weight: 500; font-variant-numeric: tabular-nums; }
.sev-card__sub { font-size: 13px; color: var(--text-2); }
.bar { height: 6px; border-radius: 3px; background: var(--surface-2); overflow: hidden; display: flex; }
.bar > i { display: block; height: 100%; }
.sev-card .bar > i { background: var(--c); }

.svc { padding: 20px 24px; margin-top: 16px; }
.svc h3 { margin: 0 0 4px; font-size: 16px; font-weight: 500; }
.svc > p { margin: 0 0 12px; font-size: 13px; color: var(--text-2); }
.svc-list { list-style: none; margin: 0; padding: 0; display: grid; gap: 2px; grid-template-columns: 1fr; }
@media (min-width: 1100px) { .svc-list { grid-template-columns: 1fr 1fr; column-gap: 32px; } }
.svc-row {
  width: 100%; display: grid; grid-template-columns: 130px 1fr auto; align-items: center; gap: 12px;
  background: none; border: 0; border-radius: var(--r-sm); padding: 6px 8px; cursor: pointer; text-align: left;
}
.svc-row:hover { background: var(--surface-2); }
.svc-row__name { font-family: var(--mono); font-size: 13px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.svc-row__bar { height: 10px; border-radius: 5px; }
.svc-row__bar > .f { background: var(--fail); }
.svc-row__bar > .p { background: var(--pass); opacity: .55; }
.svc-row__num { font-size: 13px; font-variant-numeric: tabular-nums; color: var(--text-2); white-space: nowrap; }
.svc-row__num b { color: var(--fail-text); font-weight: 600; }

/* ---------- Report information ---------- */
.info-grid { display: grid; gap: 16px; align-items: start; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); }
.info-card { padding: 0; overflow: hidden; }
.info-card h3 { margin: 0; font-size: 14px; font-weight: 500; padding: 12px 16px; background: var(--surface-2); border-bottom: 1px solid var(--border); }
.info-card dl { margin: 0; }
.info-card .kv { display: flex; justify-content: space-between; gap: 16px; padding: 10px 16px; border-bottom: 1px solid var(--border); font-size: 14px; }
.info-card .kv:last-child { border-bottom: 0; }
.info-card dt { color: var(--text-2); }
.info-card dd { margin: 0; text-align: right; font-weight: 500; overflow-wrap: anywhere; font-variant-numeric: tabular-nums; }
.info-card dd.empty { color: var(--text-2); font-weight: 400; font-style: italic; }
.logo-link { display: inline-flex; align-items: center; gap: 8px; padding: 12px 16px; font-size: 14px; }
.logo-link img { width: 9rem; height: auto; display: block; }
html[data-theme="dark"] .logo-link img { filter: invert(1) hue-rotate(180deg); }

/* ---------- Findings toolbar ---------- */
.toolbar { display: flex; flex-wrap: wrap; gap: 12px; align-items: center; padding: 12px; border-bottom: 1px solid var(--border); }
.search { position: relative; flex: 1 1 280px; max-width: 520px; }
.search svg { position: absolute; left: 12px; top: 50%; transform: translateY(-50%); color: var(--text-2); pointer-events: none; }
.search input {
  width: 100%; height: 40px; padding: 0 12px 0 40px; border-radius: 999px;
  border: 1px solid var(--border); background: var(--surface-2); color: var(--text); font: inherit; font-size: 14px;
}
.search input:focus { background: var(--surface); border-color: var(--accent); outline: none; box-shadow: 0 0 0 1px var(--accent); }
.btn {
  display: inline-flex; align-items: center; gap: 8px; height: 36px; padding: 0 14px;
  border-radius: 999px; border: 1px solid var(--border); background: var(--surface); cursor: pointer;
  font-size: 14px; font-weight: 500; color: var(--accent); white-space: nowrap;
}
.btn:hover { background: var(--accent-soft); }
.btn:active { filter: brightness(.95); }
.btn[aria-expanded="true"] { background: var(--accent-soft); border-color: var(--accent); }
.btn .count { background: var(--accent-fill); color: #fff; border-radius: 999px; font-size: 12px; padding: 0 7px; line-height: 18px; }
html[data-theme="dark"] .btn .count { color: #202124; }
.select { height: 36px; border-radius: var(--r-sm); border: 1px solid var(--border); background: var(--surface); color: var(--text); font: inherit; font-size: 14px; padding: 0 8px; }
.toolbar label { font-size: 14px; color: var(--text-2); display: inline-flex; align-items: center; gap: 8px; }
.toolbar__spacer { flex: 1 1 auto; }

.status-seg { display: inline-flex; border: 1px solid var(--border); border-radius: 999px; overflow: hidden; }
.status-seg button { border: 0; background: var(--surface); padding: 0 14px; height: 36px; cursor: pointer; font-size: 14px; color: var(--text-2); }
.status-seg button + button { border-left: 1px solid var(--border); }
.status-seg button[aria-pressed="true"] { background: var(--accent-soft); color: var(--accent); font-weight: 500; }

/* Filter panes (SearchPanes equivalent) */
.panes { display: none; padding: 16px 12px; border-bottom: 1px solid var(--border); background: var(--surface-2); }
.panes.open { display: block; }
.panes__head { display: flex; align-items: center; gap: 12px; margin-bottom: 12px; flex-wrap: wrap; }
.panes__head h3 { margin: 0; font-size: 15px; font-weight: 500; }
.panes__head p { margin: 0; font-size: 13px; color: var(--text-2); }
.panes__grid { display: grid; gap: 12px; grid-template-columns: repeat(auto-fill, minmax(230px, 1fr)); }
.pane { background: var(--surface); border: 1px solid var(--border); border-radius: var(--r-md); display: flex; flex-direction: column; min-height: 0; }
.pane.wide { grid-column: span 2; }
@media (max-width: 560px) { .pane.wide { grid-column: auto; } }
.pane__head { display: flex; align-items: center; gap: 8px; padding: 10px 12px 6px; }
.pane__head h4 { margin: 0; font-size: 14px; font-weight: 500; flex: 1; }
.pane__clear { border: 0; background: none; color: var(--accent); cursor: pointer; font-size: 13px; padding: 2px 4px; border-radius: 4px; }
.pane__clear[hidden] { display: none; }
.pane__search { margin: 0 12px 6px; height: 32px; border: 1px solid var(--border); border-radius: var(--r-sm); background: var(--surface-2); color: var(--text); font: inherit; font-size: 13px; padding: 0 10px; }
.pane__list { list-style: none; margin: 0; padding: 4px; overflow: auto; max-height: 220px; }
.pane__item label {
  display: flex; align-items: center; gap: 8px; padding: 5px 8px; border-radius: 6px; cursor: pointer; font-size: 13px;
}
.pane__item label:hover { background: var(--surface-2); }
.pane__item input { accent-color: var(--accent-fill); margin: 0; flex: none; }
.pane__item .v { flex: 1; min-width: 0; overflow-wrap: anywhere; }
.pane__item .n { color: var(--text-2); font-variant-numeric: tabular-nums; white-space: nowrap; font-size: 12px; }
.pane__item.zero { opacity: .45; }
.pane__item.empty-val .v { font-style: italic; color: var(--text-2); }

.active-filters { display: flex; flex-wrap: wrap; gap: 8px; padding: 10px 12px; border-bottom: 1px solid var(--border); align-items: center; }
.active-filters:empty { display: none; }
.fchip { display: inline-flex; align-items: center; gap: 6px; padding: 3px 4px 3px 10px; border-radius: 999px; background: var(--accent-soft); color: var(--accent); font-size: 13px; max-width: 100%; }
.fchip span { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.fchip button { border: 0; background: none; color: inherit; cursor: pointer; width: 22px; height: 22px; border-radius: 50%; display: inline-flex; align-items: center; justify-content: center; flex: none; }
.fchip button:hover { background: rgba(128,128,128,.2); }
.link-btn { border: 0; background: none; color: var(--accent); cursor: pointer; font-size: 13px; font-weight: 500; padding: 4px 6px; border-radius: 6px; }
.link-btn:hover { background: var(--accent-soft); }

.colmenu { position: relative; }
.colmenu__pop {
  position: absolute; right: 0; top: calc(100% + 6px); z-index: 20; min-width: 220px;
  background: var(--surface); border: 1px solid var(--border); border-radius: var(--r-md); box-shadow: var(--shadow); padding: 6px;
}
.colmenu__pop[hidden] { display: none; }
.colmenu__pop label { display: flex; gap: 10px; align-items: center; padding: 6px 10px; border-radius: 6px; font-size: 14px; cursor: pointer; color: var(--text); }
.colmenu__pop label:hover { background: var(--surface-2); }
.colmenu__pop input { accent-color: var(--accent-fill); }

/* ---------- Table ---------- */
.table-wrap { overflow: auto; max-height: calc(100vh - var(--header-h) - 24px); }
table.findings { width: 100%; border-collapse: separate; border-spacing: 0; font-size: 14px; }
.findings thead th {
  position: sticky; top: 0; z-index: 2;
  background: var(--surface); color: var(--text-2); font-weight: 500; text-align: left;
  border-bottom: 1px solid var(--border-strong); padding: 0; white-space: nowrap; font-size: 13px;
}
.findings thead th > button {
  width: 100%; display: flex; align-items: center; gap: 4px; padding: 12px 10px; border: 0; background: none; cursor: pointer;
  color: inherit; font: inherit; text-align: left;
}
.findings thead th > button:hover { color: var(--text); background: var(--surface-2); }
.findings thead th .sort-ic { opacity: .35; font-size: 11px; }
.findings thead th[aria-sort="ascending"] .sort-ic, .findings thead th[aria-sort="descending"] .sort-ic { opacity: 1; color: var(--accent); }
.findings thead th[aria-sort="ascending"], .findings thead th[aria-sort="descending"] { color: var(--accent); }
.findings thead th .sort-ord { font-size: 10px; color: var(--accent); }
.findings thead th.th-x { width: 44px; }

.findings tbody td { padding: 10px; border-bottom: 1px solid var(--border); vertical-align: top; overflow-wrap: anywhere; }
.findings tbody tr.row { cursor: pointer; }
.findings tbody tr.row:hover td { background: var(--surface-hover); }
.findings tbody tr.row.is-fail td:first-child { box-shadow: inset 4px 0 0 var(--fail); }
.findings tbody tr.row.is-pass td:first-child { box-shadow: inset 4px 0 0 var(--pass); }
.findings tbody tr.row.is-fail td { background: var(--row-fail); }
.findings tbody tr.row.is-fail:hover td { background: var(--surface-hover); }
.findings tbody tr.row.open td { border-bottom-color: transparent; }
td.c-check { font-family: var(--mono); font-size: 12.5px; min-width: 180px; }
.c-title { min-width: 220px; }
td.c-res { font-family: var(--mono); font-size: 12.5px; min-width: 160px; max-width: 320px; }
.c-ext { min-width: 240px; max-width: 420px; }
.c-long { min-width: 260px; max-width: 420px; }
.clamp { display: -webkit-box; -webkit-line-clamp: 3; -webkit-box-orient: vertical; overflow: hidden; }
.clamp p { margin: 0; }
.c-svc, .c-reg { white-space: nowrap; }
.muted { color: var(--text-2); font-style: italic; }

.xbtn { width: 28px; height: 28px; border-radius: 50%; border: 0; background: none; cursor: pointer; color: var(--text-2); display: inline-flex; align-items: center; justify-content: center; }
.xbtn:hover { background: var(--surface-2); color: var(--text); }
.xbtn svg { transition: transform .15s ease; }
tr.open .xbtn svg { transform: rotate(90deg); }

.badge {
  display: inline-flex; align-items: center; gap: 6px; padding: 2px 10px 2px 8px;
  border-radius: 999px; font-size: 12.5px; font-weight: 600; white-space: nowrap; line-height: 20px;
}
.badge::before { content: ""; width: 8px; height: 8px; border-radius: 50%; background: var(--dot); flex: none; }
.b-pass { background: var(--pass-bg); color: var(--pass-text); --dot: var(--pass); }
.b-fail { background: var(--fail-bg); color: var(--fail-text); --dot: var(--fail); }
.b-critical { background: var(--sev-critical-bg); color: var(--sev-critical-text); --dot: var(--sev-critical); }
.b-high { background: var(--sev-high-bg); color: var(--sev-high-text); --dot: var(--sev-high); }
.b-medium { background: var(--sev-medium-bg); color: var(--sev-medium-text); --dot: var(--sev-medium); }
.b-low { background: var(--sev-low-bg); color: var(--sev-low-text); --dot: var(--sev-low); }
.b-other { background: var(--surface-2); color: var(--text); --dot: var(--accent-fill); }
.b-pass::before { content: "\2713"; width: auto; height: auto; background: none; color: var(--pass); font-size: 12px; }
.b-fail::before { content: "\2715"; width: auto; height: auto; background: none; color: var(--fail); font-size: 11px; }
.b-critical::before { border-radius: 2px; transform: rotate(45deg); width: 7px; height: 7px; }
.b-high::before { border-radius: 2px; }
.b-low::before { border-radius: 50%; }

/* Detail row */
tr.detail > td { padding: 0 10px 16px; background: var(--surface); border-bottom: 1px solid var(--border); cursor: default; }
tr.detail.is-fail > td:first-child { box-shadow: none; }
.detail__box {
  border: 1px solid var(--border); border-radius: var(--r-md); background: var(--surface-2);
  padding: 16px 20px; display: grid; gap: 4px 24px; grid-template-columns: 1fr;
}
@media (min-width: 1000px) { .detail__box { grid-template-columns: 200px 1fr; } }
.detail__box dt { font-weight: 500; color: var(--text-2); font-size: 13px; padding-top: 10px; }
.detail__box dd { margin: 0; padding: 6px 0 10px; border-bottom: 1px solid var(--border); font-size: 14.5px; }
@media (min-width: 1000px) { .detail__box dt { padding-top: 8px; border-bottom: 1px solid var(--border); } .detail__box dd { padding-top: 8px; } }
.detail__box dd p { margin: 0; }
.detail__box dt:nth-last-child(2), .detail__box dd:last-child { border-bottom: 0; }
.detail__box .mono { font-family: var(--mono); font-size: 13px; }
.compliance { white-space: pre-line; font-size: 13.5px; }
.compliance p { margin: 0; }

/* Prowler Hub link inside Recommendation (Font Awesome icon replaced offline) */
a.read-more { display: inline-flex; align-items: center; gap: 6px; font-size: 13px; word-break: break-all; }
a.read-more::after { content: attr(href); }
.clamp a.read-more::after { content: none; }
i.fas.fa-external-link-alt {
  display: inline-block; width: 14px; height: 14px; flex: none; background: currentColor;
  -webkit-mask: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'%3E%3Cpath d='M19 19H5V5h7V3H5a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14c1.1 0 2-.9 2-2v-7h-2v7zM14 3v2h3.59l-9.83 9.83 1.41 1.41L19 6.41V10h2V3h-7z'/%3E%3C/svg%3E") center/contain no-repeat;
          mask: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'%3E%3Cpath d='M19 19H5V5h7V3H5a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14c1.1 0 2-.9 2-2v-7h-2v7zM14 3v2h3.59l-9.83 9.83 1.41 1.41L19 6.41V10h2V3h-7z'/%3E%3C/svg%3E") center/contain no-repeat;
}

/* Footer of table */
.tfoot { display: flex; flex-wrap: wrap; align-items: center; gap: 12px; padding: 12px; border-top: 1px solid var(--border); font-size: 14px; color: var(--text-2); }
.pager { display: flex; gap: 4px; margin-left: auto; flex-wrap: wrap; }
.pager button { min-width: 36px; height: 36px; padding: 0 8px; border-radius: 999px; border: 1px solid transparent; background: none; cursor: pointer; color: var(--text); font-variant-numeric: tabular-nums; }
.pager button:hover:not(:disabled) { background: var(--surface-2); }
.pager button[aria-current="page"] { background: var(--accent-soft); color: var(--accent); font-weight: 600; border-color: var(--accent); }
.pager button:disabled { opacity: .4; cursor: default; }
.pager .gap { padding: 0 4px; align-self: center; }
.empty-state { padding: 48px 16px; text-align: center; color: var(--text-2); }
.empty-state strong { display: block; color: var(--text); font-weight: 500; margin-bottom: 4px; }

/* ---------- Mobile: rows become cards ---------- */
@media (max-width: 760px) {
  .app-header__inner { flex-wrap: wrap; gap: 4px 12px; padding: 8px 12px 4px; }
  .brand { flex: 1 1 0; }
  .brand h1 { font-size: 15px; }
  .brand__meta { font-size: 12px; }
  .header-right { margin-left: 0; flex: none; }
  .header-nav { order: 3; width: 100%; margin: 0; overflow-x: auto; }
  .header-nav a { padding: 6px 12px; }
  .sev-chips { display: none; }
  main { padding: 16px 12px 40px; }
  .table-wrap { max-height: none; overflow: visible; }
  table.findings, .findings tbody, .findings tr, .findings td { display: block; width: 100%; }
  .findings thead { display: none; }
  .findings tbody tr.row { position: relative; border-bottom: 1px solid var(--border); padding: 12px 12px 12px 16px; }
  .findings tbody tr.row td { border: 0; padding: 2px 0; background: none !important; box-shadow: none !important; min-width: 0; max-width: none; }
  .findings tbody tr.row.is-fail { box-shadow: inset 4px 0 0 var(--fail); background: var(--row-fail); }
  .findings tbody tr.row.is-pass { box-shadow: inset 4px 0 0 var(--pass); }
  .findings tbody tr.row td[data-label]::before { content: attr(data-label); display: block; font-size: 12px; color: var(--text-2); margin-top: 6px; font-family: var(--font); }
  .findings tbody tr.row td.c-svc, .findings tbody tr.row td.c-reg { display: inline-block; width: 50%; vertical-align: top; }
  .findings tbody tr.row td.c-status, .findings tbody tr.row td.c-sev { display: inline-block; width: auto; margin-right: 6px; }
  .findings tbody tr.row td.c-status::before, .findings tbody tr.row td.c-sev::before { display: none !important; }
  .findings tbody tr.row td.c-x { position: absolute; right: 8px; top: 8px; width: auto; }
  tr.detail > td { padding: 0 8px 12px; }
  .pager { margin-left: 0; }
}

@media print {
  .app-header, .toolbar, .panes, .active-filters, .tfoot .pager, .xbtn, .skip { display: none !important; }
  body { background: #fff; color: #000; }
  .table-wrap { max-height: none; overflow: visible; }
  .card { break-inside: avoid; }
}
</style>
</head>
<body>
<a class="skip" href="#findings">Skip to findings</a>

<header class="app-header">
  <div class="app-header__inner">
    <div class="brand">
      <svg width="32" height="32" viewBox="0 0 32 32" aria-hidden="true">
        <path d="M16 2.5 4.5 7v8.2c0 7.1 4.9 12.6 11.5 14.3 6.6-1.7 11.5-7.2 11.5-14.3V7L16 2.5z" fill="none" stroke="var(--accent-fill)" stroke-width="2.2" stroke-linejoin="round"/>
        <path d="m10.5 16.2 3.8 3.8 7.4-7.6" fill="none" stroke="var(--accent-fill)" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"/>
      </svg>
      <div>
        <h1>{{TITLE}}</h1>
        <div class="brand__meta">{{SUBTITLE}}</div>
      </div>
    </div>
    <nav class="header-nav" aria-label="Report sections">
      <a href="#summary">Summary</a>
      <a href="#info">Report info</a>
      <a href="#findings">Findings</a>
    </nav>
    <div class="header-right">
      <div class="sev-chips" id="sevChips" aria-label="Failed findings by severity"></div>
      <button class="icon-btn" id="themeToggle" type="button" aria-label="Switch to dark mode" aria-pressed="false">
        <svg class="icon-moon-hide" width="20" height="20" viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="M12 3a9 9 0 1 0 9 9c0-.46-.04-.92-.1-1.36a5.39 5.39 0 0 1-4.4 2.26 5.4 5.4 0 0 1-3.14-9.8A9.1 9.1 0 0 0 12 3z"/></svg>
        <svg class="icon-sun-hide" width="20" height="20" viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="M12 7a5 5 0 1 0 0 10 5 5 0 0 0 0-10zM2 13h2a1 1 0 0 0 0-2H2a1 1 0 0 0 0 2zm18 0h2a1 1 0 0 0 0-2h-2a1 1 0 0 0 0 2zM11 2v2a1 1 0 0 0 2 0V2a1 1 0 0 0-2 0zm0 18v2a1 1 0 0 0 2 0v-2a1 1 0 0 0-2 0zM5.99 4.58a1 1 0 0 0-1.41 1.41l1.06 1.06a1 1 0 0 0 1.41-1.41L5.99 4.58zm12.37 12.37a1 1 0 0 0-1.41 1.41l1.06 1.06a1 1 0 0 0 1.41-1.41l-1.06-1.06zm1.06-10.96a1 1 0 0 0-1.41-1.41l-1.06 1.06a1 1 0 0 0 1.41 1.41l1.06-1.06zM7.05 18.36a1 1 0 0 0-1.41-1.41l-1.06 1.06a1 1 0 0 0 1.41 1.41l1.06-1.06z"/></svg>
      </button>
    </div>
  </div>
</header>

<main id="main">
  <!-- ========== Summary ========== -->
  <section id="summary" aria-labelledby="summary-h">
    <div class="section-head" style="margin-top:0">
      <h2 id="summary-h">Executive summary</h2>
      <p>Counts are computed from the findings table in this report. Select a card or service to filter the findings.</p>
    </div>
    <div class="summary-grid">
      <div class="card overall">
        <h3>Overall status</h3>
        <div class="donut-wrap">
          <div class="donut" id="donut"></div>
          <ul class="legend" id="donutLegend"></ul>
        </div>
        <p class="overall__note" id="passRateNote"></p>
      </div>
      <div>
        <div class="sev-cards" id="sevCards"></div>
        <div class="card svc" id="svcCard">
          <h3>Results by service</h3>
          <p>Failed (red) and passed (green) results per Service Name, sorted by failed count.</p>
          <ul class="svc-list" id="svcList"></ul>
        </div>
      </div>
    </div>
  </section>

  <!-- ========== Report information (all original header data) ========== -->
  <section id="info" aria-labelledby="info-h">
    <div class="section-head"><h2 id="info-h">Report information</h2></div>
    <div class="info-grid">
{{INFO_CARDS}}
    </div>
  </section>

  <!-- ========== Findings ========== -->
  <section id="findings" aria-labelledby="findings-h">
    <div class="section-head">
      <h2 id="findings-h">Findings</h2>
      <p id="findingsSub"></p>
    </div>
    <div class="card" style="overflow:hidden">
      <div class="toolbar" role="search">
        <div class="search">
          <svg width="18" height="18" viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="M15.5 14h-.79l-.28-.27A6.47 6.47 0 0 0 16 9.5 6.5 6.5 0 1 0 9.5 16c1.61 0 3.09-.59 4.23-1.57l.27.28v.79l5 4.99L20.49 19l-4.99-5zm-6 0C7.01 14 5 11.99 5 9.5S7.01 5 9.5 5 14 7.01 14 9.5 11.99 14 9.5 14z"/></svg>
          <label for="q" class="sr-only">Search all findings</label>
          <input id="q" type="search" placeholder="Search all columns" autocomplete="off" spellcheck="false" />
        </div>
        <div class="status-seg" role="group" aria-label="Quick status filter">
          <button type="button" data-st="" aria-pressed="true">All</button>
          <button type="button" data-st="FAIL" aria-pressed="false">Fail</button>
          <button type="button" data-st="PASS" aria-pressed="false">Pass</button>
        </div>
        <button class="btn" id="panesBtn" type="button" aria-expanded="false" aria-controls="panes">
          <svg width="18" height="18" viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="M10 18h4v-2h-4v2zM3 6v2h18V6H3zm3 7h12v-2H6v2z"/></svg>
          <span id="panesBtnLabel">Filters</span>
        </button>
        <span class="toolbar__spacer"></span>
        <div class="colmenu">
          <button class="btn" id="colBtn" type="button" aria-expanded="false" aria-controls="colPop">Columns</button>
          <div class="colmenu__pop" id="colPop" hidden></div>
        </div>
        <button class="btn" id="expandAll" type="button">Expand page</button>
        <button class="btn" id="exportCsv" type="button" title="Download the currently filtered and sorted findings as CSV">Export CSV</button>
      </div>
      <div class="panes" id="panes">
        <div class="panes__head">
          <h3>Filters</h3>
          <p>Values within a filter are combined with OR, filters with AND. Counts update with other active filters.</p>
          <span class="toolbar__spacer"></span>
          <button class="link-btn" id="clearAll" type="button">Clear Filters</button>
        </div>
        <div class="panes__grid" id="panesGrid"></div>
      </div>
      <div class="active-filters" id="activeFilters" aria-live="polite"></div>
      <div class="table-wrap" id="tableWrap">
        <table class="findings" id="findingsTable">
          <caption class="sr-only">Prowler findings. Select a row to show full details.</caption>
          <thead><tr id="theadRow"></tr></thead>
          <tbody id="tbody"></tbody>
        </table>
        <div class="empty-state" id="emptyState" hidden><strong>No findings match the current search and filters.</strong>Clear the search or remove a filter to see results.</div>
      </div>
      <div class="tfoot">
        <label>Show
          <select class="select" id="pageLen" aria-label="Rows per page">
            <option value="25">25</option><option value="50">50</option><option value="100" selected>100</option><option value="-1">All</option>
          </select>
          entries</label>
        <span id="info-line" aria-live="polite"></span>
        <nav class="pager" id="pager" aria-label="Pagination"></nav>
      </div>
    </div>
  </section>
</main>

<!-- Original table rows, losslessly encoded: "cols" are the original column headers, "s" is a table of unique cell HTML
     strings exactly as they appeared inside the original <td> elements, and each row in "r" is [rowClass, col0..colN] as indexes into "s". -->
<script type="application/json" id="report-data">{{DATA}}</script>
<script type="application/json" id="report-config">{{CONFIG}}</script>
<script>
(function () {
  'use strict';
  var D = JSON.parse(document.getElementById('report-data').textContent);
  var CFG = JSON.parse(document.getElementById('report-config').textContent);
  var S = D.s, R = D.r, N = R.length, COLS = D.cols, NC = COLS.length;

  /* Column roles are resolved by header name, so a different column order still works */
  function col(name) { for (var i = 0; i < NC; i++) if (COLS[i].trim().toLowerCase() === name.toLowerCase()) return i; return -1; }
  var C_STATUS = col('Status'), C_SEV = col('Severity'), C_SVC = col('Service Name'), C_REGION = col('Region'),
      C_CHECK = col('Check ID'), C_TITLE = col('Check Title'), C_RES = col('Resource ID'), C_TAGS = col('Resource Tags'),
      C_EXT = col('Status Extended'), C_RISK = col('Risk'), C_REC = col('Recommendation'), C_COMP = col('Compliance');

  var PANE_COLS = (CFG.paneCols || []).filter(function (c) { return c >= 0 && c < NC; });
  var SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, informational: 4 };
  var STATUS_ORDER = { FAIL: 0, MANUAL: 1, MUTED: 2, PASS: 3 };
  var COL_CLASS = COLS.map(function (n, c) {
    if (c === C_STATUS) return 'c-status'; if (c === C_SEV) return 'c-sev'; if (c === C_SVC) return 'c-svc';
    if (c === C_REGION) return 'c-reg'; if (c === C_CHECK) return 'c-check'; if (c === C_TITLE) return 'c-title';
    if (c === C_RES) return 'c-res'; if (c === C_TAGS) return 'c-tags'; if (c === C_EXT) return 'c-ext';
    if (c === C_RISK || c === C_REC || c === C_COMP) return 'c-long';
    return 'c-other';
  });

  /* ---------- Text helpers ---------- */
  var decoder = document.createElement('textarea');
  var plainCache = new Array(S.length);
  function plain(i) {
    var v = plainCache[i];
    if (v === undefined) {
      var h = S[i].replace(/<wbr\s*\/?>/gi, '').replace(/<br\s*\/?>/gi, '\n').replace(/<[^>]*>/g, ' ');
      decoder.innerHTML = h;
      v = decoder.value.replace(/[ \t]+/g, ' ').trim();
      plainCache[i] = v;
    }
    return v;
  }
  var lowerCache = new Array(S.length);
  function lower(i) { var v = lowerCache[i]; if (v === undefined) { v = plain(i).toLowerCase(); lowerCache[i] = v; } return v; }
  function esc(s) { return String(s).replace(/[&<>"']/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; }); }
  function fmt(n) { return n.toLocaleString('en-US'); }
  function cell(r, c) { return R[r][c + 1]; }
  function cap(s) { return s.charAt(0).toUpperCase() + s.slice(1); }
  function statusOf(r) { return C_STATUS >= 0 ? plain(cell(r, C_STATUS)).toUpperCase() : ''; }

  function sevBadge(txt) {
    var k = txt.toLowerCase();
    var cls = SEV_ORDER.hasOwnProperty(k) && k !== 'informational' ? 'b-' + k : 'b-other';
    return '<span class="badge ' + cls + '">' + esc(cap(txt)) + '</span>';
  }
  function statusBadge(txt) {
    var u = txt.toUpperCase();
    var cls = u === 'PASS' ? 'b-pass' : (u === 'FAIL' ? 'b-fail' : 'b-other');
    return '<span class="badge ' + cls + '">' + esc(txt) + '</span>';
  }

  /* ---------- Theme ---------- */
  var themeBtn = document.getElementById('themeToggle');
  function syncThemeBtn() {
    var dark = document.documentElement.getAttribute('data-theme') === 'dark';
    themeBtn.setAttribute('aria-pressed', dark ? 'true' : 'false');
    themeBtn.setAttribute('aria-label', dark ? 'Switch to light mode' : 'Switch to dark mode');
    themeBtn.title = dark ? 'Light mode' : 'Dark mode';
  }
  themeBtn.addEventListener('click', function () {
    var next = document.documentElement.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', next);
    try { window.localStorage.setItem('prowler-report-theme', next); } catch (e) {}
    syncThemeBtn();
  });
  syncThemeBtn();

  /* ---------- Summary (derived only from rows) ---------- */
  var sevStats = {}, svcStats = {}, passN = 0, failN = 0, otherN = 0, otherLabels = {};
  for (var r = 0; r < N; r++) {
    var st = statusOf(r);
    var key = st === 'FAIL' ? 'fail' : (st === 'PASS' ? 'pass' : 'other');
    if (key === 'other') otherLabels[st || '(empty)'] = 1;
    if (C_SEV >= 0) {
      var sv = plain(cell(r, C_SEV)).toLowerCase();
      if (!sevStats[sv]) sevStats[sv] = { fail: 0, pass: 0, other: 0 };
      sevStats[sv][key]++;
    }
    if (C_SVC >= 0) {
      var svc = plain(cell(r, C_SVC));
      if (!svcStats[svc]) svcStats[svc] = { fail: 0, pass: 0, other: 0, idx: cell(r, C_SVC) };
      svcStats[svc][key]++;
    }
    if (key === 'fail') failN++; else if (key === 'pass') passN++; else otherN++;
  }
  var sevKeys = Object.keys(sevStats).sort(function (a, b) {
    return (SEV_ORDER.hasOwnProperty(a) ? SEV_ORDER[a] : 9) - (SEV_ORDER.hasOwnProperty(b) ? SEV_ORDER[b] : 9);
  });

  if (C_STATUS < 0) { document.getElementById('summary').hidden = true; }
  (function donut() {
    if (C_STATUS < 0) return;
    var total = N, rad = 60, circ = 2 * Math.PI * rad;
    var segs = [{ n: failN, c: 'var(--fail)', l: 'Failed' }, { n: passN, c: 'var(--pass)', l: 'Passed' }];
    if (otherN) segs.push({ n: otherN, c: 'var(--gcp-grey-500)', l: 'Other (' + Object.keys(otherLabels).join(', ') + ')' });
    var off = 0, svg = '<svg width="148" height="148" viewBox="0 0 148 148" role="img" aria-label="Failed ' + failN + ', passed ' + passN + ' of ' + total + ' findings">';
    svg += '<circle cx="74" cy="74" r="' + rad + '" fill="none" stroke="var(--surface-2)" stroke-width="16"/>';
    segs.forEach(function (s) {
      var len = total ? circ * s.n / total : 0;
      svg += '<circle cx="74" cy="74" r="' + rad + '" fill="none" stroke="' + s.c + '" stroke-width="16" stroke-dasharray="' + len + ' ' + (circ - len) + '" stroke-dashoffset="' + (-off) + '"/>';
      off += len;
    });
    svg += '</svg>';
    var pct = total ? (passN / total * 100) : 0;
    document.getElementById('donut').innerHTML = svg + '<div class="donut__center"><strong>' + pct.toFixed(1) + '%</strong><span>passed</span></div>';
    document.getElementById('donutLegend').innerHTML = segs.map(function (s) {
      return '<li><span class="swatch" style="background:' + s.c + '"></span>' + esc(s.l) + '<b>' + fmt(s.n) + '</b></li>';
    }).join('') + '<li><span class="swatch" style="background:transparent"></span>Total<b>' + fmt(total) + '</b></li>';
    document.getElementById('passRateNote').textContent = 'Pass rate is passed results divided by all ' + fmt(total) + ' results in the table.';
  })();

  var sevCardsHtml = '', chipsHtml = '';
  sevKeys.forEach(function (k) {
    var s = sevStats[k], tot = s.fail + s.pass + s.other, label = k ? cap(k) : '(empty)';
    var v = SEV_ORDER.hasOwnProperty(k) && k !== 'informational' ? k : null;
    var c = v ? 'var(--sev-' + v + ')' : 'var(--accent-fill)', ct = v ? 'var(--sev-' + v + '-text)' : 'var(--accent)';
    sevCardsHtml += '<button type="button" class="sev-card" data-sev="' + esc(k) + '" style="--c:' + c + ';--ct:' + ct + '" aria-label="Show failed ' + esc(label) + ' findings">' +
      '<span class="sev-card__label"><span class="badge ' + (v ? 'b-' + v : 'b-other') + '" style="background:none;padding:0;color:inherit">' + esc(label) + '</span></span>' +
      '<span class="sev-card__num">' + fmt(s.fail) + '</span>' +
      '<span class="sev-card__sub">failed of ' + fmt(tot) + ' results, ' + fmt(s.pass) + ' passed</span>' +
      '<span class="bar" aria-hidden="true"><i style="width:' + (tot ? s.fail / tot * 100 : 0) + '%"></i></span></button>';
    chipsHtml += '<button type="button" class="sev-chip" data-sev="' + esc(k) + '" title="Failed ' + esc(label) + ' findings">' +
      '<span class="swatch" style="background:' + c + '"></span>' + esc(label) + ' <b>' + fmt(s.fail) + '</b></button>';
  });
  if (C_STATUS >= 0) {
    sevCardsHtml += '<button type="button" class="sev-card" data-pass="1" style="--c:var(--pass);--ct:var(--pass-text)" aria-label="Show passed findings">' +
      '<span class="sev-card__label"><span class="badge b-pass" style="background:none;padding:0">Pass</span></span>' +
      '<span class="sev-card__num">' + fmt(passN) + '</span>' +
      '<span class="sev-card__sub">passed of ' + fmt(N) + ' results</span>' +
      '<span class="bar" aria-hidden="true"><i style="width:' + (N ? passN / N * 100 : 0) + '%"></i></span></button>';
  }
  document.getElementById('sevCards').innerHTML = sevCardsHtml;
  document.getElementById('sevChips').innerHTML = chipsHtml;

  var svcKeys = Object.keys(svcStats).sort(function (a, b) {
    return (svcStats[b].fail - svcStats[a].fail) || ((svcStats[b].pass + svcStats[b].fail) - (svcStats[a].pass + svcStats[a].fail)) || a.localeCompare(b);
  });
  if (!svcKeys.length) document.getElementById('svcCard').hidden = true;
  var svcMax = 0; svcKeys.forEach(function (k) { var s = svcStats[k]; svcMax = Math.max(svcMax, s.fail + s.pass + s.other); });
  document.getElementById('svcList').innerHTML = svcKeys.map(function (k) {
    var s = svcStats[k], t = s.fail + s.pass + s.other;
    return '<li><button type="button" class="svc-row" data-svc="' + s.idx + '" aria-label="Filter findings by service ' + esc(k) + ': ' + s.fail + ' failed, ' + s.pass + ' passed">' +
      '<span class="svc-row__name">' + esc(k || '(empty)') + '</span>' +
      '<span class="bar svc-row__bar" style="width:' + Math.max(2, t / svcMax * 100) + '%"><i class="f" style="width:' + (s.fail / t * 100) + '%"></i><i class="p" style="width:' + (s.pass / t * 100) + '%"></i></span>' +
      '<span class="svc-row__num"><b>' + fmt(s.fail) + '</b> / ' + fmt(t) + '</span></button></li>';
  }).join('');

  /* ---------- Table state ---------- */
  var HIDDEN_BY_DEFAULT = [C_TAGS, C_RISK, C_REC, C_COMP];
  var state = {
    q: '', sel: {},
    sort: (CFG.order || []).filter(function (o) { return o[0] >= 0 && o[0] < NC; }).map(function (o) { return [o[0], o[1] === 'desc' ? 'desc' : 'asc']; }),
    len: CFG.pageLength || 100, page: 0, open: {}, visible: {}
  };
  for (var vc = 0; vc < NC; vc++) state.visible[vc] = HIDDEN_BY_DEFAULT.indexOf(vc) === -1 ? 1 : 0;
  PANE_COLS.forEach(function (c) { state.sel[c] = new Set(); });
  var view = [];

  /* Search: like DataTables "smart" search - every space separated term must appear somewhere in the row */
  function searchMask() {
    var terms = state.q.toLowerCase().split(/\s+/).filter(Boolean);
    if (!terms.length) return null;
    var hit = terms.map(function (t) {
      var m = new Uint8Array(S.length);
      for (var i = 0; i < S.length; i++) if (lower(i).indexOf(t) !== -1) m[i] = 1;
      return m;
    });
    var out = new Uint8Array(N);
    for (var r = 0; r < N; r++) {
      var row = R[r], ok = true;
      for (var t = 0; t < hit.length && ok; t++) {
        var m = hit[t], f = false;
        for (var c = 1; c <= NC; c++) if (m[row[c]]) { f = true; break; }
        ok = f;
      }
      out[r] = ok ? 1 : 0;
    }
    return out;
  }

  var paneCounts = {};
  function compute() {
    var sm = searchMask();
    PANE_COLS.forEach(function (c) { paneCounts[c] = {}; });
    view = [];
    for (var r = 0; r < N; r++) {
      if (sm && !sm[r]) continue;
      var failing = -1, nf = 0;
      for (var p = 0; p < PANE_COLS.length; p++) {
        var c = PANE_COLS[p], set = state.sel[c];
        if (set.size && !set.has(cell(r, c))) { nf++; failing = c; if (nf > 1) break; }
      }
      if (nf === 0) {
        view.push(r);
        for (var p2 = 0; p2 < PANE_COLS.length; p2++) { var c2 = PANE_COLS[p2], v2 = cell(r, c2); paneCounts[c2][v2] = (paneCounts[c2][v2] || 0) + 1; }
      } else if (nf === 1) {
        var v = cell(r, failing); paneCounts[failing][v] = (paneCounts[failing][v] || 0) + 1;
      }
    }
    sortView();
  }

  function sortKey(c, i) {
    if (c === C_SEV) { var k = lower(i); return SEV_ORDER.hasOwnProperty(k) ? SEV_ORDER[k] : 9; }
    if (c === C_STATUS) { var s = plain(i).toUpperCase(); return STATUS_ORDER.hasOwnProperty(s) ? STATUS_ORDER[s] : 5; }
    return lower(i);
  }
  var collator = (window.Intl && Intl.Collator) ? new Intl.Collator('en', { numeric: true, sensitivity: 'base' }) : null;
  function cmp(a, b) {
    if (typeof a === 'number') return a - b;
    return collator ? collator.compare(a, b) : (a < b ? -1 : a > b ? 1 : 0);
  }
  function sortView() {
    var specs = state.sort;
    if (!specs.length) return;
    view.sort(function (x, y) {
      for (var i = 0; i < specs.length; i++) {
        var c = specs[i][0], d = specs[i][1] === 'asc' ? 1 : -1;
        var a = cell(x, c), b = cell(y, c);
        if (a === b) continue;
        var r = cmp(sortKey(c, a), sortKey(c, b));
        if (r) return r * d;
      }
      return x - y;
    });
  }

  /* ---------- Rendering ---------- */
  var thead = document.getElementById('theadRow');
  function renderHead() {
    var h = '<th class="th-x" scope="col"><span class="sr-only">Details</span></th>';
    for (var c = 0; c < NC; c++) {
      if (!state.visible[c]) continue;
      var si = -1, dir = null;
      for (var i = 0; i < state.sort.length; i++) if (state.sort[i][0] === c) { si = i; dir = state.sort[i][1]; }
      var aria = dir ? (dir === 'asc' ? 'ascending' : 'descending') : 'none';
      var ic = dir === 'asc' ? '\u25B2' : dir === 'desc' ? '\u25BC' : '\u21C5';
      h += '<th scope="col" aria-sort="' + aria + '" class="' + COL_CLASS[c] + '"><button type="button" data-sort="' + c + '" title="Sort by ' + esc(COLS[c]) + ' (Shift+click to add a secondary sort)">' +
        esc(COLS[c]) + ' <span class="sort-ic" aria-hidden="true">' + ic + '</span>' + (state.sort.length > 1 && si >= 0 ? '<span class="sort-ord">' + (si + 1) + '</span>' : '') + '</button></th>';
    }
    thead.innerHTML = h;
  }

  function cellHtml(r, c, full) {
    var i = cell(r, c), raw = S[i];
    if (c === C_STATUS) return statusBadge(plain(i));
    if (c === C_SEV) return sevBadge(plain(i));
    if (!plain(i) && !/<a\s/i.test(raw)) return '<span class="muted">(empty)</span>';
    /* display only: collapse the blank lines between compliance entries (stored data unchanged) */
    if (c === C_COMP) return '<div class="compliance">' + raw.replace(/\n[ \t]*\n/g, '\n').replace(/(<p[^>]*>)\s*\n/, '$1').replace(/\n\s*(<\/p>)\s*$/, '$1') + '</div>';
    if (!full && (c === C_EXT || c === C_RISK || c === C_REC || COL_CLASS[c] === 'c-other')) return '<div class="clamp">' + raw + '</div>';
    return raw;
  }

  var tbody = document.getElementById('tbody');
  var expandBtn = document.getElementById('expandAll');
  function visibleCount() { var n = 0; for (var c = 0; c < NC; c++) if (state.visible[c]) n++; return n; }
  function detailHtml(r, isFail) {
    var h = '<tr class="detail' + (isFail ? ' is-fail' : '') + '" data-detail="' + r + '"><td colspan="' + (visibleCount() + 1) + '"><dl class="detail__box">';
    for (var c = 0; c < NC; c++) {
      var mono = (c === C_CHECK || c === C_RES) ? ' class="mono"' : '';
      h += '<dt>' + esc(COLS[c]) + '</dt><dd' + mono + '>' + cellHtml(r, c, true) + '</dd>';
    }
    return h + '</dl></td></tr>';
  }

  function render() {
    var total = view.length, len = state.len < 0 ? total : state.len;
    var pages = Math.max(1, Math.ceil(total / (len || 1)));
    if (state.page >= pages) state.page = pages - 1;
    var start = state.len < 0 ? 0 : state.page * len, end = Math.min(total, start + len);
    var out = [];
    for (var k = start; k < end; k++) {
      var r = view[k], st = statusOf(r), isFail = st === 'FAIL', isPass = st === 'PASS', open = !!state.open[r];
      var lbl = (C_CHECK >= 0 ? plain(cell(r, C_CHECK)) : 'row ' + (r + 1)) + (C_RES >= 0 ? ' on ' + plain(cell(r, C_RES)) : '');
      var h = '<tr class="row ' + (isFail ? 'is-fail' : isPass ? 'is-pass' : '') + (open ? ' open' : '') + '" data-r="' + r + '">' +
        '<td class="c-x"><button type="button" class="xbtn" aria-expanded="' + open + '" aria-label="' + (open ? 'Hide' : 'Show') + ' details for ' + esc(lbl) + '">' +
        '<svg width="18" height="18" viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="M8.6 16.6 13.2 12 8.6 7.4 10 6l6 6-6 6z"/></svg></button></td>';
      for (var c = 0; c < NC; c++) {
        if (!state.visible[c]) continue;
        h += '<td class="' + COL_CLASS[c] + '" data-label="' + esc(COLS[c]) + '">' + cellHtml(r, c, false) + '</td>';
      }
      h += '</tr>';
      if (open) h += detailHtml(r, isFail);
      out.push(h);
    }
    tbody.innerHTML = out.join('');
    document.getElementById('emptyState').hidden = total !== 0;
    var filtered = total !== N;
    document.getElementById('info-line').textContent = total
      ? 'Showing ' + fmt(start + 1) + ' to ' + fmt(end) + ' of ' + fmt(total) + ' entries' + (filtered ? ' (filtered from ' + fmt(N) + ' total entries)' : '')
      : 'Showing 0 to 0 of 0 entries' + (filtered ? ' (filtered from ' + fmt(N) + ' total entries)' : '');
    document.getElementById('findingsSub').textContent = filtered ? fmt(total) + ' of ' + fmt(N) + ' results match' : fmt(N) + ' results';
    renderPager(pages);
    var anyClosed = false;
    for (var k2 = start; k2 < end; k2++) if (!state.open[view[k2]]) { anyClosed = true; break; }
    expandBtn.textContent = anyClosed ? 'Expand page' : 'Collapse page';
  }

  var pager = document.getElementById('pager');
  function renderPager(pages) {
    if (state.len < 0 || pages <= 1) { pager.innerHTML = ''; return; }
    var p = state.page, h = '<button type="button" data-pg="' + (p - 1) + '"' + (p === 0 ? ' disabled' : '') + ' aria-label="Previous page">Previous</button>';
    var nums = [];
    if (pages <= 7) { for (var i = 0; i < pages; i++) nums.push(i); }
    else {
      nums.push(0);
      var a = Math.max(1, p - 1), b = Math.min(pages - 2, p + 1);
      if (p <= 2) { a = 1; b = 3; } if (p >= pages - 3) { a = pages - 4; b = pages - 2; }
      if (a > 1) nums.push('…');
      for (var j = a; j <= b; j++) nums.push(j);
      if (b < pages - 2) nums.push('…');
      nums.push(pages - 1);
    }
    nums.forEach(function (n) {
      h += n === '…' ? '<span class="gap" aria-hidden="true">…</span>' :
        '<button type="button" data-pg="' + n + '"' + (n === p ? ' aria-current="page"' : '') + ' aria-label="Page ' + (n + 1) + '">' + (n + 1) + '</button>';
    });
    h += '<button type="button" data-pg="' + (p + 1) + '"' + (p >= pages - 1 ? ' disabled' : '') + ' aria-label="Next page">Next</button>';
    pager.innerHTML = h;
  }

  /* ---------- Filter panes ---------- */
  var panesGrid = document.getElementById('panesGrid');
  var paneSearch = {}, PANE_VALUES = {}, TOTALS = {};
  PANE_COLS.forEach(function (c) {
    var seen = {}, vals = [];
    TOTALS[c] = {};
    for (var r = 0; r < N; r++) { var v = cell(r, c); TOTALS[c][v] = (TOTALS[c][v] || 0) + 1; if (!seen[v]) { seen[v] = 1; vals.push(v); } }
    vals.sort(function (a, b) { return cmp(sortKey(c, a), sortKey(c, b)); });
    PANE_VALUES[c] = vals; paneSearch[c] = '';
  });
  if (!PANE_COLS.length) document.getElementById('panesBtn').hidden = true;

  function buildPanes() {
    panesGrid.innerHTML = PANE_COLS.map(function (c) {
      return '<div class="pane' + (c === C_TITLE ? ' wide' : '') + '" data-pane="' + c + '">' +
        '<div class="pane__head"><h4 id="ph' + c + '">' + esc(COLS[c]) + '</h4><button type="button" class="pane__clear" data-clear="' + c + '" hidden>Clear</button></div>' +
        '<input class="pane__search" type="search" data-psearch="' + c + '" placeholder="Search ' + esc(COLS[c]) + '" aria-label="Search ' + esc(COLS[c]) + ' values" />' +
        '<ul class="pane__list" role="group" aria-labelledby="ph' + c + '"></ul></div>';
    }).join('');
  }
  function anyFilter() {
    if (state.q.trim()) return true;
    for (var i = 0; i < PANE_COLS.length; i++) if (state.sel[PANE_COLS[i]].size) return true;
    return false;
  }
  function renderPanes() {
    PANE_COLS.forEach(function (c) {
      var pane = panesGrid.querySelector('[data-pane="' + c + '"]');
      var q = paneSearch[c].toLowerCase(), set = state.sel[c], active = anyFilter();
      var items = PANE_VALUES[c].filter(function (v) { return !q || lower(v).indexOf(q) !== -1; });
      items.sort(function (a, b) {
        var sa = set.has(a) ? 0 : (paneCounts[c][a] ? 1 : 2), sb = set.has(b) ? 0 : (paneCounts[c][b] ? 1 : 2);
        return sa - sb || PANE_VALUES[c].indexOf(a) - PANE_VALUES[c].indexOf(b);
      });
      pane.querySelector('.pane__list').innerHTML = items.map(function (v) {
        var n = paneCounts[c][v] || 0, t = TOTALS[c][v], txt = plain(v);
        var cnt = active ? fmt(n) + ' / ' + fmt(t) : fmt(t);
        return '<li class="pane__item' + (n ? '' : ' zero') + (txt ? '' : ' empty-val') + '"><label><input type="checkbox" data-pc="' + c + '" value="' + v + '"' + (set.has(v) ? ' checked' : '') + ' />' +
          '<span class="v">' + (txt ? esc(txt) : 'No data') + '</span><span class="n">' + cnt + '</span></label></li>';
      }).join('') || '<li class="pane__item"><label><span class="v muted">No matching values</span></label></li>';
      pane.querySelector('.pane__clear').hidden = !set.size;
    });
  }
  function selCount() { var n = 0; PANE_COLS.forEach(function (c) { n += state.sel[c].size ? 1 : 0; }); return n; }

  var activeEl = document.getElementById('activeFilters');
  var statusSeg = document.querySelector('.status-seg');
  if (C_STATUS < 0 || PANE_COLS.indexOf(C_STATUS) === -1) statusSeg.hidden = true;
  function renderActive() {
    var h = '';
    PANE_COLS.forEach(function (c) {
      state.sel[c].forEach(function (v) {
        var txt = plain(v) || 'No data';
        h += '<span class="fchip"><span>' + esc(COLS[c]) + ': ' + esc(txt) + '</span><button type="button" data-rm="' + c + ':' + v + '" aria-label="Remove filter ' + esc(COLS[c] + ' ' + txt) + '">' +
          '<svg width="14" height="14" viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="M19 6.4 17.6 5 12 10.6 6.4 5 5 6.4 10.6 12 5 17.6 6.4 19 12 13.4 17.6 19 19 17.6 13.4 12z"/></svg></button></span>';
      });
    });
    if (h) h += '<button type="button" class="link-btn" data-clearall="1">Clear Filters</button>';
    activeEl.innerHTML = h;
    var n = selCount();
    document.getElementById('panesBtnLabel').textContent = n ? 'Filters (' + n + ')' : 'Filters';
    if (statusSeg.hidden) return;
    var stSet = state.sel[C_STATUS], only = null;
    if (stSet.size === 1) stSet.forEach(function (v) { only = plain(v).toUpperCase(); });
    statusSeg.querySelectorAll('button').forEach(function (b) {
      var st = b.getAttribute('data-st');
      b.setAttribute('aria-pressed', (st === '' && !stSet.size) || (only !== null && st === only) ? 'true' : 'false');
    });
  }

  var panesEl = document.getElementById('panes'), panesBtn = document.getElementById('panesBtn');
  function refresh() {
    state.page = 0;
    compute(); renderHead(); render(); renderActive();
    if (panesEl.classList.contains('open')) renderPanes();
  }

  /* ---------- Column menu ---------- */
  var colPop = document.getElementById('colPop'), colBtn = document.getElementById('colBtn');
  colPop.innerHTML = COLS.map(function (n, c) {
    return '<label><input type="checkbox" data-col="' + c + '"' + (state.visible[c] ? ' checked' : '') + ' />' + esc(n) + '</label>';
  }).join('');
  colBtn.addEventListener('click', function (e) {
    e.stopPropagation();
    var open = colPop.hidden; colPop.hidden = !open; colBtn.setAttribute('aria-expanded', open ? 'true' : 'false');
  });
  colPop.addEventListener('change', function (e) {
    var c = +e.target.getAttribute('data-col');
    state.visible[c] = e.target.checked ? 1 : 0;
    if (!visibleCount()) { state.visible[c] = 1; e.target.checked = true; }
    renderHead(); render();
  });
  document.addEventListener('click', function (e) {
    if (!colPop.hidden && !colPop.contains(e.target) && e.target !== colBtn) { colPop.hidden = true; colBtn.setAttribute('aria-expanded', 'false'); }
  });
  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape' && !colPop.hidden) { colPop.hidden = true; colBtn.setAttribute('aria-expanded', 'false'); colBtn.focus(); }
  });

  /* ---------- Events ---------- */
  var qInput = document.getElementById('q'), qTimer = null;
  qInput.addEventListener('input', function () {
    clearTimeout(qTimer);
    qTimer = setTimeout(function () { state.q = qInput.value; refresh(); }, 180);
  });

  thead.addEventListener('click', function (e) {
    var b = e.target.closest('button[data-sort]'); if (!b) return;
    var c = +b.getAttribute('data-sort'), idx = -1;
    for (var i = 0; i < state.sort.length; i++) if (state.sort[i][0] === c) idx = i;
    if (e.shiftKey) {
      if (idx >= 0) state.sort[idx][1] = state.sort[idx][1] === 'asc' ? 'desc' : 'asc'; else state.sort.push([c, 'asc']);
    } else {
      var dir = idx >= 0 && state.sort.length === 1 && state.sort[0][1] === 'asc' ? 'desc' : 'asc';
      state.sort = [[c, dir]];
    }
    sortView(); renderHead(); render();
  });

  tbody.addEventListener('click', function (e) {
    if (e.target.closest('a')) return;
    var tr = e.target.closest('tr.row'); if (!tr) return;
    if (!e.target.closest('.xbtn') && window.getSelection && String(window.getSelection()).length) return;
    var r = +tr.getAttribute('data-r');
    if (state.open[r]) delete state.open[r]; else state.open[r] = 1;
    render();
    var btn = tbody.querySelector('tr.row[data-r="' + r + '"] .xbtn'); if (btn && e.target.closest('.xbtn')) btn.focus();
  });

  expandBtn.addEventListener('click', function () {
    var len = state.len < 0 ? view.length : state.len, start = state.len < 0 ? 0 : state.page * len, end = Math.min(view.length, start + len);
    var anyClosed = false, k;
    for (k = start; k < end; k++) if (!state.open[view[k]]) { anyClosed = true; break; }
    for (k = start; k < end; k++) { if (anyClosed) state.open[view[k]] = 1; else delete state.open[view[k]]; }
    render();
  });

  pager.addEventListener('click', function (e) {
    var b = e.target.closest('button[data-pg]'); if (!b || b.disabled) return;
    state.page = +b.getAttribute('data-pg'); render();
    document.getElementById('findings').scrollIntoView();
    document.getElementById('tableWrap').scrollTop = 0;
  });
  var pageLen = document.getElementById('pageLen');
  pageLen.value = String(state.len);
  if (pageLen.value !== String(state.len)) { var o = document.createElement('option'); o.value = String(state.len); o.textContent = String(state.len); pageLen.insertBefore(o, pageLen.firstChild); pageLen.value = String(state.len); }
  pageLen.addEventListener('change', function (e) { state.len = +e.target.value; state.page = 0; render(); });

  buildPanes();
  panesBtn.addEventListener('click', function () {
    var open = !panesEl.classList.contains('open');
    panesEl.classList.toggle('open', open); panesBtn.setAttribute('aria-expanded', open ? 'true' : 'false');
    if (open) renderPanes();
  });
  panesGrid.addEventListener('change', function (e) {
    var cb = e.target.closest('input[data-pc]'); if (!cb) return;
    var c = +cb.getAttribute('data-pc'), v = +cb.value;
    if (cb.checked) state.sel[c].add(v); else state.sel[c].delete(v);
    refresh();
  });
  panesGrid.addEventListener('input', function (e) {
    var s = e.target.closest('input[data-psearch]'); if (!s) return;
    paneSearch[+s.getAttribute('data-psearch')] = s.value; renderPanes();
  });
  panesGrid.addEventListener('click', function (e) {
    var b = e.target.closest('button[data-clear]'); if (!b) return;
    state.sel[+b.getAttribute('data-clear')].clear(); refresh();
  });
  function clearSel() { PANE_COLS.forEach(function (c) { state.sel[c].clear(); }); }
  document.getElementById('clearAll').addEventListener('click', function () { clearSel(); refresh(); });
  activeEl.addEventListener('click', function (e) {
    var b = e.target.closest('button'); if (!b) return;
    if (b.hasAttribute('data-clearall')) { clearSel(); refresh(); return; }
    var p = b.getAttribute('data-rm').split(':'); state.sel[+p[0]].delete(+p[1]); refresh();
  });

  /* Shortcuts (cards, chips, services, status segment) need the column to be one of the filter panes */
  function canFilter(c) { return c >= 0 && PANE_COLS.indexOf(c) !== -1; }
  function valueIndex(c, txt) {
    var vals = PANE_VALUES[c] || [], t = txt.toLowerCase();
    for (var i = 0; i < vals.length; i++) if (lower(vals[i]) === t) return vals[i];
    return -1;
  }
  function setStatus(st) {
    if (!canFilter(C_STATUS)) return;
    state.sel[C_STATUS].clear();
    if (st) { var vi = valueIndex(C_STATUS, st); if (vi >= 0) state.sel[C_STATUS].add(vi); }
  }
  statusSeg.addEventListener('click', function (e) {
    var b = e.target.closest('button[data-st]'); if (!b) return;
    setStatus(b.getAttribute('data-st')); refresh();
  });
  function gotoFindings() { document.getElementById('findings').scrollIntoView(); }
  function sevFilter(e) {
    var b = e.target.closest('[data-sev],[data-pass]'); if (!b) return;
    clearSel();
    if (b.hasAttribute('data-pass')) setStatus('PASS');
    else { setStatus('FAIL'); if (canFilter(C_SEV)) { var vi = valueIndex(C_SEV, b.getAttribute('data-sev')); if (vi >= 0) state.sel[C_SEV].add(vi); } }
    refresh(); gotoFindings();
  }
  document.getElementById('sevCards').addEventListener('click', sevFilter);
  document.getElementById('sevChips').addEventListener('click', sevFilter);
  document.getElementById('svcList').addEventListener('click', function (e) {
    var b = e.target.closest('[data-svc]'); if (!b) return;
    if (!canFilter(C_SVC)) return;
    clearSel(); state.sel[C_SVC].add(+b.getAttribute('data-svc'));
    refresh(); gotoFindings();
  });

  /* CSV export of the current filtered + sorted view, all columns as plain text */
  document.getElementById('exportCsv').addEventListener('click', function () {
    function q(s) { s = String(s); if (/^[=+\-@\t\r]/.test(s)) s = "'" + s; return '"' + s.replace(/"/g, '""') + '"'; }
    var lines = [COLS.map(q).join(',')];
    view.forEach(function (r) {
      var row = [];
      for (var c = 0; c < NC; c++) {
        var t = plain(cell(r, c));
        var links = S[cell(r, c)].match(/href="([^"]+)"/g);
        if (links) links.forEach(function (l) { var u = l.slice(6, -1); if (t.indexOf(u) === -1) t += (t ? ' ' : '') + u; });
        row.push(q(t));
      }
      lines.push(row.join(','));
    });
    var blob = new Blob(['\uFEFF' + lines.join('\r\n')], { type: 'text/csv;charset=utf-8' });
    var a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'prowler-findings-' + (CFG.fileTag || 'report') + '-' + view.length + '.csv';
    document.body.appendChild(a); a.click();
    setTimeout(function () { URL.revokeObjectURL(a.href); a.remove(); }, 500);
  });

  var navLinks = document.querySelectorAll('.header-nav a');
  if ('IntersectionObserver' in window) {
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (en) {
        if (en.isIntersecting) navLinks.forEach(function (a) { a.setAttribute('aria-current', a.getAttribute('href') === '#' + en.target.id ? 'true' : 'false'); });
      });
    }, { rootMargin: '-30% 0px -60% 0px' });
    ['summary', 'info', 'findings'].forEach(function (id) { var el = document.getElementById(id); if (el) io.observe(el); });
  }

  refresh();
})();
</script>
</body>
</html>
"""


if __name__ == "__main__":
    sys.exit(main())
