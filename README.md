# Weakness → Control Map

Map software weaknesses (MITRE CWE) and attack patterns (MITRE CAPEC) to NIST SP 800-53 Rev 5 security controls
and NIST Secure Software Development Framework (SSDF, SP 800-218 v1.1) tasks, and back again: from a control or an
SSDF task to the weaknesses it addresses. Every link says where it came from, so you can tell an official
reference from a rule-derived link or a machine-inferred one.

It is built for agents that work with security findings. When a scanner report, a code review or a threat model
names a CWE or CAPEC, the agent can answer "which controls and SSDF practices apply?" in a few lines, without loading
large reference documents into the conversation.

Version 1.0.0 · Claude Code, claude.ai and GitHub Copilot CLI · offline · MIT licensed

## Example

```text
$ lookup.py CWE-89
CWE-89 Improper Neutralization of Special Elements used in an SQL Command [Base, Stable, CWE mapping usage: Allowed]
800-53: CM-6 Configuration Settings[m,r]; CM-7 Least Functionality[m,r]; SC-7 Boundary Protection[m,r]; SI-10 Information Input Validation[m,r]; SI-15 Information Output Filtering[m,r]; SA-11(1) Static Code Analysis[d,t]; SA-11(2) Threat Modeling and Vulnerability…[d,t]; SA-11(4) Manual Code Reviews[d,t]; SA-11(8) Dynamic Code Analysis[d,t]; SA-17 Developer Security and Privacy Ar…[d,t]; AC-6 Least Privilege[m,x]
SSDF 1.1: PW.4.1[m,r]; PW.4.4[m,r]; PW.5.1[m,r]; PW.2.1[d,t]; PW.7.2[d,t]; PW.8.2[d,t]; PW.1.1[m,p]
inferred, NOT reviewed: SI-10(6) Injection Prevention[m,iu]
CAPEC (6): CAPEC-108 CAPEC-109 CAPEC-110 CAPEC-470 CAPEC-66 CAPEC-7
baseline (every software weakness): 800-53 SA-8 SA-11 SA-15 SI-2 RA-5 | SSDF RV.1.2 RV.2.2 RV.3.1 RV.3.3
key: m=mitigates d=detects g=governs | r/t/x/p=rule from CWE fields, o=official, ia=reviewed inference, iu=unreviewed

$ lookup.py CWE-79 CAPEC-66 SI-10 --brief
CWE-79: CM-6 CM-7 SC-7 SI-10 SI-15 SA-11(1) SA-11(8) SI-10(6)? | SSDF PW.1.1 PW.4.1 PW.4.4 PW.5.1 PW.7.2 PW.8.2
CAPEC-66: CWE CWE-1286 CWE-89 | AC-6? SI-10? SI-10(6)? SI-11? | SSDF PW.5.1?
SI-10 Information Input Validation: 160 CWE/CAPEC
```

In `--brief` output, `ID?` marks a link that was inferred and has not yet been reviewed by a person.

## Install

- **Claude Code, from this repository:**
  `/plugin marketplace add Arunktr123/weakness-control-map`, then `/plugin install weakness-control-map@weakness-control-map`
- **GitHub Copilot CLI:** `copilot plugin install Arunktr123/weakness-control-map`
- **Other agents that read `SKILL.md` folders:** copy `skills/weakness-control-map/` into the agent's skills folder.

The skill loads only when a request is about CWE, CAPEC, SP 800-53 or SSDF mapping. Its always-on cost is under 200
tokens (Claude Code's estimate), and each lookup prints a few short lines.

## What it runs, sends and stores

The plugin is one skill. When it is used, the agent runs `skills/weakness-control-map/scripts/lookup.py` with the ids or search
words from your request. The script uses only the Python 3.8+ standard library and reads the JSON files bundled in
`skills/weakness-control-map/data/`. It makes no network connections, sends nothing anywhere, writes nothing to disk, and has no
hooks, MCP servers or background processes. See [PRIVACY.md](PRIVACY.md).

## Where the links come from

There is no official MITRE or NIST mapping from CWE or CAPEC to SP 800-53 or the SSDF. SP 800-53 Rev 5 mentions CWE
only in RA-5, and CWE and CAPEC carry no NIST taxonomy mappings. So each link carries an evidence code:

| code | meaning |
|---|---|
| `o` | official: the SSDF's own references to SP 800-53 |
| `r` `t` `x` `p` | deterministic rules applied to MITRE CWE fields: mitigation strategy, detection method, mitigation text, SDLC phase |
| `ia` | inferred, then accepted by a reviewer |
| `iu` | inferred and **not yet reviewed** |

Relations: `m` mitigates, `d` detects or verifies, `g` governs. A baseline (SP 800-53 SA-8, SA-11, SA-15, SI-2, RA-5;
SSDF RV.1.2, RV.2.2, RV.3.1, RV.3.3) applies to every software weakness and is shown once rather than per weakness.
Links through ATT&CK (CAPEC → ATT&CK technique → SP 800-53, from the MITRE Center for Threat-Informed Defense) are
broad, so they appear only when you ask for them with `--expand`.

This release contains 380 inferred links for a priority set of 168 weaknesses and attack
patterns (including the CWE Top 25). They were proposed with the help of a language model and semantic search, each
with a short rationale (`--why`); none has been reviewed yet. Treat unreviewed links as a starting point for your own analysis. The tool is a mapping aid, not a compliance attestation: no result means "not mapped here", not "not
applicable".

Coverage: 699 of 956 CWE weaknesses have SP 800-53 links and 851 have SSDF links; 558 CAPEC attack patterns, 140 of them with ATT&CK links.

## Data versions

- SP 800-53: Rev 5 (5.2.0, OSCAL 2026-10-22)
- SSDF: SP 800-218 v1.1 (2022)
- CWE: 5.0
- CAPEC: 3.9
- ATT&CK->800-53: CTID Mappings Explorer, ATT&CK 16.1 (updated 04/16/2025)
- CAPEC->ATT&CK: CAPEC 3.9 taxonomy mappings (historical, ATT&CK 12.0)

## Feedback and corrections

Open an issue at https://github.com/Arunktr123/weakness-control-map/issues. For a mapping correction, give the CWE or CAPEC id, the control or SSDF task, and
why the link should be added, changed or removed.

## License

The plugin's code, rules and inferred mappings are released under the [MIT License](LICENSE). The bundled reference
data comes from MITRE CWE, CAPEC and ATT&CK, the MITRE Center for Threat-Informed Defense Mappings Explorer, and NIST
publications, each under its own terms; see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). This project is not
affiliated with or endorsed by The MITRE Corporation or NIST. CWE, CAPEC and ATT&CK are trademarks of The MITRE
Corporation.
