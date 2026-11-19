# Changelog

## 1.1.0 (unreleased)

- FedRAMP Consolidated Rules 2026 (release 2026.11.02.01): 46 KSIs and the security-practice rules (VDR, VER, SCG, CMU,
  SCN, IEC, MAS) with FedRAMP's official SP 800-53 controls, 20x/Rev5 applicability and class variants.
- KSI/rule ↔ CWE/CAPEC links: derived through the official controls (`dv`, ranked and capped) and inferred directly
  (`iu`, with rationales). Attack paths: CAPEC → ATT&CK 16.1 techniques. VDR/VER rules shown once as a baseline.
- CWE, CAPEC and control records list the KSIs and rules that address or cite them (`F`).

## 1.0.3 (2026-11-18)

- Documentation brought in line with the Anthropic Software Directory Policy: example prompts, troubleshooting, support
  and security-reporting sections, SECURITY.md, and an accurate statement of which hosts have been tested.
  The skill also names a shell `grep -E` fallback for hosts without a Grep tool. Data and mappings are unchanged.

## 1.0.2 (2026-11-17)

- Re-release with no content changes, to refresh the directory scan now that the repository is public.

## 1.0.1 (2026-11-17)

- The public edition is now script-free (Markdown, JSON and text files only), as the plugin directory requires of
  publishers that are not Verified organizations. The agent finds a record by searching the bundled data with its
  built-in search tool; a lookup returns one record of about 100 tokens. Icon converted to PNG. Mappings unchanged.

## 1.0.0 (2026-11-17)

First public release.

- One skill, `weakness-control-map`: CWE / CAPEC ↔ NIST SP 800-53 Rev 5 ↔ NIST SSDF 1.1 lookups, with an evidence
  code and relation on every link, and reverse lookups from a control or an SSDF task.
- Sources: CWE 5.0, CAPEC 3.9, SP 800-53 Rev 5.2.0, SSDF 1.1, CTID Mappings Explorer (ATT&CK 16.1).
- 380 inferred links for 168 priority CWEs and CAPECs, all marked as not yet reviewed.
- Lookups through a stdlib-only Python script reading packed data buckets.
