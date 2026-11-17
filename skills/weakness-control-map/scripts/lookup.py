#!/usr/bin/env python3
"""weakness-control-map lookup: CWE / CAPEC <-> NIST SP 800-53 Rev 5 controls <-> NIST SSDF 1.1 tasks.

Token-efficient by design: reads only the small bucket file holding the requested id and prints a few short lines.
  lookup.py  CWE-79                  weakness -> controls / SSDF tasks / related CAPEC
  lookup.py  CAPEC-66 --expand       attack pattern (+ controls derived via its CWEs and via ATT&CK)
  lookup.py  SI-10                   control -> weaknesses / attack patterns / SSDF tasks
  lookup.py  PW.5.1                  SSDF task -> official 800-53 refs / weaknesses
  lookup.py  T1190                   ATT&CK technique -> controls (CTID)
  lookup.py  CWE-79 CWE-89 --brief   one line per id (best for many findings)
  lookup.py  find "sql injection"    search names (top 10)
  lookup.py  legend | baseline | about
Flags: --why (rationales + rule provenance)  --all (full reverse lists)  --expand (derived/broad links)  --json
Python 3.8+, standard library only.
"""
import json
import zlib
import os
import re
import sys

DATA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "data")
_cache = {}
REL = {"m": "mitigates", "d": "detects", "g": "governs"}


def _load(*parts):
    p = os.path.join(DATA, *parts)
    if p not in _cache:
        try:
            with open(p, encoding="utf-8") as fh:
                _cache[p] = json.load(fh)
        except FileNotFoundError:
            _cache[p] = None
    return _cache[p]


def rec(k, i):
    """Record for id i of kind k from its bucket file data/<k>/pNN.json (bucket = crc32(id) % packs[k])."""
    n = meta().get("packs", {}).get(k)
    if not n:
        return None
    return (_load(k, f"p{zlib.crc32(i.encode('utf-8')) % n:02d}.json") or {}).get(i)


def names():
    return _load("names.json") or {}


def meta():
    return _load("meta.json") or {}


def short(s, n=34):
    s = s or ""
    return s if len(s) <= n else s[: n - 1] + "…"


def title(tid):
    n = names()
    if tid in n.get("nist", {}):
        return n["nist"][tid]
    return n.get("ssdf", {}).get(tid) or n.get("cwe", {}).get(tid) or n.get("capec", {}).get(tid) or ""


def fmt(rows, with_titles=True, limit=None):
    out = []
    for t, rel, ev in rows[:limit] if limit else rows:
        lab = f"{t} {short(title(t))}" if with_titles else t
        out.append(f"{lab}[{rel},{ev}]")
    more = len(rows) - limit if limit and len(rows) > limit else 0
    return "; ".join(out) + (f"; …(+{more}, use --all)" if more else "")


def kind(i):
    u = i.upper()
    if re.fullmatch(r"CWE-\d+", u):
        return "cwe", u
    if re.fullmatch(r"CAPEC-\d+", u):
        return "capec", u
    if re.fullmatch(r"T\d{4}(\.\d{3})?", u):
        return "att", u
    if re.fullmatch(r"(PO|PS|PW|RV)\.\d+\.\d+", u):
        return "ssdf", u
    m = re.fullmatch(r"([A-Z]{2})-0*(\d+)(?:\(0*(\d+)\))?", u)
    if m:
        return "ctl", f"{m.group(1)}-{int(m.group(2))}" + (f"({int(m.group(3))})" if m.group(3) else "")
    return None, i


def split_inferred(rows):
    keep = [r for r in rows if r[2] != "iu"]
    unrev = [r for r in rows if r[2] == "iu"]
    return keep, unrev


def agg(lists, top=10):
    c = {}
    for l in lists:
        for t in set(l):
            c[t] = c.get(t, 0) + 1
    return sorted(c.items(), key=lambda kv: (-kv[1], kv[0]))[:top]


def show_cwe(d, a):
    out = [f"{d['id']} {d['n']} [{d['ab']}, {d['st']}, CWE mapping usage: {d['mu']}]"]
    n, nu = split_inferred(d["N"])
    s, su = split_inferred(d["S"])
    out.append("800-53: " + (fmt(n) or "(no specific control beyond baseline)"))
    out.append("SSDF 1.1: " + (fmt(s, with_titles=False) or "(none beyond baseline)"))
    if nu or su:
        out.append("inferred, NOT reviewed: " + fmt(nu + su))
    if d.get("K"):
        out.append(f"CAPEC ({len(d['K'])}): " + " ".join(d["K"][: None if a.all else 8]) + ("" if a.all or len(d["K"]) <= 8 else " …"))
    if a.why:
        for t, why in (d.get("W") or {}).items():
            out.append(f"  why {t}: {why}")
        for t, p in (d.get("P") or {}).items():
            out.append(f"  rule {t}: {p}")
    if a.expand and d.get("K"):
        atts = [(rec("capec", c) or {}).get("A", []) for c in d["K"]]
        ctl = agg([(rec("att", t) or {}).get("N", []) for ts in atts for t in ts])
        if ctl:
            out.append("broad, via CAPEC->ATT&CK->800-53 (CTID): " + ", ".join(f"{t}×{k}" for t, k in ctl))
    out.append(baseline_line())
    return out


def show_capec(d, a):
    out = [f"{d['id']} {d['n']} [{d['ab']}, {d['st']}, severity {d.get('sv') or 'n/a'}]",
           f"CWE ({len(d['K'])}): " + " ".join(d["K"][: None if a.all else 10]) + ("" if a.all or len(d["K"]) <= 10 else " …")]
    if d.get("A"):
        out.append("ATT&CK (CAPEC 3.9, historical): " + " ".join(d["A"]))
    n, nu = split_inferred(d["N"])
    s, su = split_inferred(d["S"])
    if n or s:
        out.append("800-53: " + fmt(n) + (" | SSDF: " + fmt(s, False) if s else ""))
    if nu or su:
        out.append("inferred, NOT reviewed: " + fmt(nu + su))
    if a.why:
        for t, why in (d.get("W") or {}).items():
            out.append(f"  why {t}: {why}")
    if a.expand or not (n or s):
        via = agg([[r[0] for r in (rec("cwe", c) or {}).get("N", []) if r[2] != "iu"] for c in d["K"]], 12)
        if via:
            out.append("derived via its CWEs (controls×#CWEs): " + ", ".join(f"{t}×{k}" for t, k in via))
        if a.expand and d.get("A"):
            ctl = agg([(rec("att", t) or {}).get("N", []) for t in d["A"]])
            out.append("broad, via ATT&CK (CTID): " + ", ".join(f"{t}×{k}" for t, k in ctl))
    out.append(baseline_line())
    return out


def show_ctl(d, a):
    lim = None if a.all else 15
    cwe = [r for r in d["R"] if r[0].startswith("CWE-")]
    cap = [r for r in d["R"] if r[0].startswith("CAPEC-")]
    out = [f"{d['id']} {d['t']} [family {d['f']}{', BASELINE for all software weaknesses' if d.get('B') else ''}]"]
    if d.get("S"):
        out.append("official SSDF 1.1 tasks citing it: " + " ".join(d["S"]))
    out.append(f"CWE ({len(cwe)}): " + (fmt(cwe, False, lim) or "-"))
    if cap:
        out.append(f"CAPEC ({len(cap)}): " + fmt(cap, False, lim))
    if d.get("A"):
        out.append(f"mitigates {d['A']} ATT&CK techniques per CTID 16.1 (look up a technique id, e.g. T1190, for detail)")
    return out


def show_ssdf(d, a):
    lim = None if a.all else 15
    out = [f"{d['id']} (practice {d['p']}){' BASELINE' if d.get('B') else ''}: {short(d['t'], 160)}",
           "official SP 800-53 refs: " + (" ".join(d["N"]) or "none"),
           f"CWE/CAPEC ({len(d['R'])}): " + (fmt(d["R"], False, lim) or "-")]
    return out


def show_att(d, a):
    return [f"{d['id']} {d['n']}", "800-53 (CTID 'mitigates', broad): " + " ".join(d["N"])]


def baseline_line():
    b = meta().get("baseline", {})
    return "baseline (every software weakness): 800-53 " + " ".join(b.get("nist", [])) + " | SSDF " + " ".join(b.get("ssdf", []))


def _ids(rows):  # '?' = inferred, not yet reviewed
    return " ".join(r[0] + ("?" if r[2] == "iu" else "") for r in rows)


def brief(k, i, d):
    if k == "cwe":
        return f"{i}: " + _ids(d["N"]) + " | SSDF " + _ids(d["S"])
    if k == "capec":
        return f"{i}: CWE " + " ".join(d["K"][:8]) + (" | " + _ids(d["N"]) if d["N"] else "") + \
               (" | SSDF " + _ids(d["S"]) if d.get("S") else "")
    if k == "ctl":
        return f"{i} {short(d['t'])}: {len(d['R'])} CWE/CAPEC" + ("; SSDF " + " ".join(d["S"]) if d.get("S") else "")
    if k == "ssdf":
        return f"{i}: " + ("800-53 " + " ".join(d["N"]) + "; " if d.get("N") else "") + f"{len(d['R'])} CWE/CAPEC"
    return f"{i}: " + " ".join(d.get("N", []))


def find(q):
    toks = [t for t in re.split(r"\W+", q.lower()) if t]
    aka = _load("aka.json") or {}
    hits = {}
    for typ, m in names().items():
        for i, n in m.items():
            hay = " ".join([i, n] + aka.get(i, [])).lower()
            if all(t in hay for t in toks):
                exact_alias = any(all(t in a.lower() for t in toks) for a in aka.get(i, []))
                hits[i] = (0 if exact_alias else 1, len(n), i, n)
    return [f"{i} {short(n, 70)}" for _, _, i, n in sorted(hits.values())[:10]] or ["no match"]


class A:
    def __init__(self, argv):
        self.why = "--why" in argv
        self.all = "--all" in argv
        self.expand = "--expand" in argv
        self.json = "--json" in argv
        self.brief = "--brief" in argv
        self.args = [x for x in argv if not x.startswith("--")]


def main(argv):
    a = A(argv)
    if not a.args or a.args[0] in ("-h", "help"):
        print(__doc__.strip())
        return 0
    cmd = a.args[0].lower()
    if cmd == "find":
        print("\n".join(find(" ".join(a.args[1:]))))
        return 0
    if cmd == "legend":
        lg = meta().get("legend", {})
        print("rel: " + ", ".join(f"{k}={v}" for k, v in lg.get("rel", {}).items()))
        print("ev: " + ", ".join(f"{k}={v}" for k, v in lg.get("ev", {}).items()))
        return 0
    if cmd == "baseline":
        print(baseline_line())
        print("why: " + meta().get("baseline", {}).get("why", ""))
        return 0
    if cmd == "about":
        m = meta()
        print("sources: " + "; ".join(f"{k}: {v}" for k, v in m.get("sources", {}).items()))
        print(f"built {m.get('built_utc', '')[:10]} | rules {m.get('rules_version')} | counts {m.get('counts')}")
        print(m.get("attribution", ""))
        return 0
    rc = 0
    for raw in a.args:
        k, i = kind(raw)
        d = rec(k, i) if k else None
        if d is None:
            print(f"{raw}: not found (ids: CWE-79, CAPEC-66, SI-10, SA-11(1), PW.5.1, T1190; or: find <words>)")
            rc = 1
            continue
        if a.json:
            print(json.dumps(d, ensure_ascii=False))
        elif a.brief or len(a.args) > 1:
            print(brief(k, i, d))
        else:
            print("\n".join({"cwe": show_cwe, "capec": show_capec, "ctl": show_ctl, "ssdf": show_ssdf, "att": show_att}[k](d, a)))
    if not a.json and not a.brief and len(a.args) == 1 and k in ("cwe", "capec"):
        print("key: m=mitigates d=detects g=governs | r/t/x/p=rule from CWE fields, o=official, ia=reviewed inference, iu=unreviewed")
    return rc


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
