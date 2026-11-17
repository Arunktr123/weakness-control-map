# Changelog

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
