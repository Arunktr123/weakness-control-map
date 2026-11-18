---
name: weakness-control-map
description: Map MITRE CWE weaknesses and CAPEC attack patterns to NIST SP 800-53 Rev 5 controls and NIST SSDF (SP 800-218 v1.1) tasks, and reverse (control or SSDF task -> weaknesses). Use for compliance/control mapping, secure-development requirements, threat-model or remediation planning, or when a finding names a CWE/CAPEC and the user asks which NIST controls or SSDF practices apply.
---

# Weakness → control map (CWE / CAPEC ↔ SP 800-53 Rev 5 ↔ SSDF 1.1)

The data is bundled as text files with **one JSON record per line** in this skill's `data/` folder. Never read a whole
file: search for the id with the Grep tool (regex, content output, path = `<this skill's base directory>/data`). If the host has no Grep tool, run the same pattern with `grep -rE '<pattern>' <base>/data` in a shell.

| want | Grep pattern (regex) |
|---|---|
| one id | `^\{"id":"CWE-89"` · `^\{"id":"CAPEC-66"` · `^\{"id":"SI-10"` · `^\{"id":"PW\.5\.1"` · `^\{"id":"T1190"` |
| control with enhancement | escape the parentheses: `^\{"id":"SA-11\(1\)"` |
| several ids at once | `^\{"id":"(CWE-79\|CWE-89\|CAPEC-66)"` |
| rationales for an id | `^\{"why":"CWE-89"` (path `data/why`) |
| search by name or alias | case-insensitive `sql injection`, path `data/names` (lines are `ID \| name \| aka`) |

Control ids are unpadded (`AC-2`, not `AC-02`). Each result line is a complete record, about 100 tokens.

## Record fields
- **CWE** `{"id","n":name,"ab":abstraction,"st":status,"mu":mapping usage,"N":[[control,rel,ev]],"S":[[ssdf task,rel,ev]],"K":[CAPEC ids]}`
- **CAPEC** `{"id","n","ab","st","sv":severity,"K":[CWE ids],"A":[ATT&CK ids],"N":[[control,rel,ev]],"S":[[ssdf task,rel,ev]]}`
  (`N`/`S` hold inferred links only; more controls derive through its CWEs `K`.)
- **Control** `{"id","t":title,"f":family,"R":[[CWE/CAPEC,rel,ev]],"S":[ssdf tasks],"A":#ATT&CK techniques,"B":baseline}`;
  `R` is capped at 40, with `"more"` giving how many were left out.
- **SSDF task** `{"id","t":text,"p":practice,"N":[official 800-53 ids],"R":[[CWE/CAPEC,rel,ev]],"B"}`
- **ATT&CK technique** `{"id","n","N":[control ids]}`
- **why** `{"why":id,"W":{target:rationale},"P":{target:rule provenance}}`

## How to report results
- Each link is `[target, relation, evidence]`. relation: `m` mitigates, `d` detects/verifies, `g` governs.
  evidence: `o` official (SSDF's own SP 800-53 references), `r`/`t`/`x`/`p` deterministic rules from MITRE CWE fields
  (mitigation strategy, detection method, mitigation text, SDLC phase), `ia` inferred and reviewer-accepted,
  `iu` inferred and **not yet reviewed**: always say so when citing an `iu` link.
- To name a control or SSDF task, look up its id; titles are in its record (`t`) and in `data/names`.
- Baseline, applies to every software weakness; mention it once, not per weakness: SP 800-53 SA-8, SA-11, SA-15, SI-2, RA-5;
  SSDF RV.1.2, RV.2.2, RV.3.1, RV.3.3.
- Links derived through a CAPEC's CWEs, or through ATT&CK (`A` → technique record → controls), are indirect and broad:
  label them "derived", not as specific mappings.
- With many findings, search all ids in one Grep call and summarise; do not look up every control title.
- There is no official MITRE or NIST CWE/CAPEC → 800-53 mapping; this is a mapping aid, not an attestation.
  No result means "not mapped here", not "not applicable".
