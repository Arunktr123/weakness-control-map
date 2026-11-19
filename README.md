# Weakness → Control Map

Map software weaknesses (MITRE CWE) and attack patterns (MITRE CAPEC) to NIST SP 800-53 Rev 5 security controls
and NIST Secure Software Development Framework (SSDF, SP 800-218 v1.1) tasks, and back again: from a control or an
SSDF task to the weaknesses it addresses. Every link says where it came from, so you can tell an official
reference from a rule-derived link or a machine-inferred one.

It is built for agents that work with security findings. When a scanner report, a code review or a threat model
names a CWE or CAPEC, the agent can answer "which controls and SSDF practices apply?" in a few lines, without loading
large reference documents into the conversation.

Version 1.1.0 · built for Claude Code and claude.ai · offline · MIT licensed

## Example

The agent finds a record by searching the bundled data for its id (pattern `^\{"id":"CWE-89"`) and gets one line back:

```text
{"id":"CWE-89","n":"Improper Neutralization of Special Elements used in an SQL Command","ab":"Base","st":"Stable","mu":"Allowed","N":[["CM-6","m","r"],["CM-7","m","r"],["SC-7","m","r"],["SI-10","m","r"],["SI-15","m","r"],["SA-11(1)","d","t"],["SA-11(2)","d","t"],["SA-11(4)","d","t"],["SA-11(8)","d","t"],["SA-17","d","t"],["AC-6","m","x"],["SI-10(6)","m","iu"]],"S":[["PW.4.1","m","r"],["PW.4.4","m","r"],["PW.5.1","m","r"],["PW.2.1","d","t"],["PW.7.2","d","t"],["PW.8.2","d","t"],["PW.1.1","m","p"]],"K":["CAPEC-108","CAPEC-109","CAPEC-110","CAPEC-470","CAPEC-66","CAPEC-7"],"F":[["KSI-SVC-EIS","m","dv"]]}
```

Each link is `[target, relation, evidence]`; evidence `iu` marks a link that was inferred and has not yet been reviewed
by a person. The agent turns records into a readable answer.

## Install

- **Claude Code, from this repository:**
  `/plugin marketplace add Arunktr123/weakness-control-map`, then `/plugin install weakness-control-map@weakness-control-map`
- **GitHub Copilot CLI:** the repository includes a Copilot `plugin.json` (`copilot plugin install Arunktr123/weakness-control-map`). This has not been tested yet.
- **Other agents that read `SKILL.md` folders:** copy `skills/weakness-control-map/` into the agent's skills folder.

The skill loads only when a request is about CWE, CAPEC, SP 800-53 or SSDF mapping. Its always-on cost is under 200
tokens (Claude Code's estimate), and a lookup returns one record of about 100 tokens.

## Example prompts

1. "Which NIST SP 800-53 controls and SSDF tasks apply to CWE-89 (SQL injection)? Say which links are unreviewed."
2. "Our scanner reported CWE-79, CWE-22 and CWE-798. Give me one table of the controls and SSDF tasks for each, for the
   compliance report."
3. "Which weaknesses and attack patterns does control SI-10 help with?"
4. "What does CAPEC-66 map to, and which of those links are official versus inferred?"
5. "For FedRAMP KSI-SVC-VRI, which weaknesses and ATT&CK techniques does it address?"

Each is answered from the bundled data in one or two searches. The agent should cite the evidence code of every link.

## What it runs, sends and stores

The plugin is one skill made only of Markdown and JSON text files. It contains no scripts, hooks, MCP servers, commands
or background processes, and it asks for no permissions. When it is used, the agent searches the files in
`skills/weakness-control-map/data/` with its own built-in search tool. Nothing is sent anywhere, written to disk, or kept. See
[PRIVACY.md](PRIVACY.md).

## Where the links come from

There is no official MITRE or NIST mapping from CWE or CAPEC to SP 800-53 or the SSDF. SP 800-53 Rev 5 mentions CWE
only in RA-5, and CWE and CAPEC carry no NIST taxonomy mappings. So each link carries an evidence code:

| code | meaning |
|---|---|
| `o` | official: the SSDF's own references to SP 800-53 |
| `r` `t` `x` `p` | deterministic rules applied to MITRE CWE fields: mitigation strategy, detection method, mitigation text, SDLC phase |
| `ia` | inferred, then accepted by a reviewer |
| `iu` | inferred and **not yet reviewed** |
| `f` | official FedRAMP: the KSI or rule lists the SP 800-53 control |
| `dv` | derived: CWE/CAPEC reached through a KSI's or rule's official controls (ranked; withheld when the controls cannot separate them) |

Relations: `m` mitigates, `d` detects or verifies, `g` governs. A baseline (SP 800-53 SA-8, SA-11, SA-15, SI-2, RA-5;
SSDF RV.1.2, RV.2.2, RV.3.1, RV.3.3) applies to every software weakness and is shown once rather than per weakness.
Links through ATT&CK (CAPEC → ATT&CK technique → SP 800-53, from the MITRE Center for Threat-Informed Defense) are
broad, so they appear only when you ask for them with `--expand`.

**FedRAMP Consolidated Rules 2026 (CR26).** The 46 Key Security Indicators (KSIs) and the rules in the security-practice
families (VDR, VER, SCG, CMU, SCN, IEC, MAS) are included. Each keeps FedRAMP's own SP 800-53 control list (`f`),
its 20x / Rev5 applicability and every class variant (a–d) that FedRAMP defines. CWE and CAPEC links are derived
through those controls (`dv`) or inferred directly (`iu`). Attack paths follow MITRE's CAPEC → ATT&CK links, checked
against ATT&CK 16.1. Vulnerability Detection and Response (VDR) and Vulnerability Evaluation and Reporting (VER)
rules apply to every weakness and are shown once as a baseline.

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
- FedRAMP: FedRAMP Consolidated Rules for 2026 (2026.11.02.01, updated 2026-11-02)

## Troubleshooting

- **"Not found" or no result:** the id may not be in the data. Use the exact id form (`CWE-89`, `CAPEC-66`, `SI-10`,
  `SA-11(1)`, `PW.5.1`); control ids are unpadded (`AC-2`, not `AC-02`). Names and aliases can be searched too,
  for example "sql injection". Weaknesses that were deprecated or are only categories are not included.
- **No result is not "not applicable".** It means the pair is not mapped here.
- **The skill does not trigger:** mention CWE, CAPEC, SP 800-53 or SSDF in the request, or ask for the
  "weakness-control-map" skill by name.
- **Too much output:** ask for a summary table; controls such as SA-11(1) have long reverse lists, which are capped at 40.
- **No search tool in the agent:** the skill falls back to `grep -E` in a shell. Without either, the agent cannot read the data.

## Support and security

Questions and mapping corrections: open an issue at https://github.com/Arunktr123/weakness-control-map/issues. Security problems with this repository: see
[SECURITY.md](SECURITY.md). Maintenance: reported problems are triaged on a best-effort basis and data releases follow
new CWE, CAPEC and NIST publications.

## Feedback and corrections

Open an issue at https://github.com/Arunktr123/weakness-control-map/issues. For a mapping correction, give the CWE or CAPEC id, the control or SSDF task, and
why the link should be added, changed or removed.

## License

The plugin's code, rules and inferred mappings are released under the [MIT License](LICENSE). The bundled reference
data comes from MITRE CWE, CAPEC and ATT&CK, the MITRE Center for Threat-Informed Defense Mappings Explorer, and NIST
publications, each under its own terms; see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). This project is not
affiliated with or endorsed by The MITRE Corporation or NIST. CWE, CAPEC and ATT&CK are trademarks of The MITRE
Corporation.
