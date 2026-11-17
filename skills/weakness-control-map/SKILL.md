---
name: weakness-control-map
description: Map MITRE CWE weaknesses and CAPEC attack patterns to NIST SP 800-53 Rev 5 controls and NIST SSDF (SP 800-218 v1.1) tasks, and reverse (control or SSDF task -> weaknesses). Use for compliance/control mapping, secure-development requirements, threat-model or remediation planning, or when a finding names a CWE/CAPEC and the user asks which NIST controls or SSDF practices apply.
---

# Weakness → control map (CWE / CAPEC ↔ SP 800-53 Rev 5 ↔ SSDF 1.1)

Run the bundled lookup; never open the `data/` files directly (they are packed buckets; the script prints only what is needed).
It is offline: Python 3.8+ standard library, no network, nothing written to disk.

```bash
python3 <this-skill-dir>/scripts/lookup.py CWE-79            # weakness -> controls, SSDF, CAPEC
python3 <this-skill-dir>/scripts/lookup.py CAPEC-66           # attack pattern -> CWEs, controls
python3 <this-skill-dir>/scripts/lookup.py SI-10              # control -> weaknesses (reverse)
python3 <this-skill-dir>/scripts/lookup.py PW.5.1             # SSDF task -> official 800-53 refs, weaknesses
python3 <this-skill-dir>/scripts/lookup.py CWE-79 CWE-89 CWE-22 --brief   # many ids: one line each (cheapest)
python3 <this-skill-dir>/scripts/lookup.py find "sql injection"           # name / alias search
```
Flags only when needed: `--why` (rationale + rule provenance), `--all` (full reverse lists), `--expand`
(derived links via CWEs and the broad ATT&CK chain), `--json`. `legend`, `baseline`, `about` print reference info.

## How to report results
- Prefer `--brief` for more than two ids; fetch detail only for the ids the user cares about.
- Each link is `ID[relation,evidence]`. relation: m mitigates, d detects/verifies, g governs.
  evidence: o official (SSDF's own SP 800-53 references), r/t/x/p deterministic rules from MITRE CWE fields
  (mitigation strategy, detection method, mitigation text, SDLC phase), ia inferred and reviewer-accepted,
  iu inferred and **not yet reviewed** — always say so when citing an `iu` link (shown as `ID?` in `--brief`).
- The baseline line (SA-8, SA-11, SA-15, SI-2, RA-5; SSDF RV.1.2, RV.2.2, RV.3.1, RV.3.3) applies to every
  software weakness; mention it once, not per weakness.
- `--expand` results are derived or broad (ATT&CK-technique level), not specific mappings — label them that way.
- There is no official MITRE or NIST CWE/CAPEC → 800-53 mapping; this is a mapping aid, not an attestation.
  No result means "not mapped here", not "not applicable".
