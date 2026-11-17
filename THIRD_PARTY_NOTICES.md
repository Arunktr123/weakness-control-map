# Third-party notices

The files in `skills/weakness-control-map/data/` contain identifiers, names and relationships taken or derived from
the sources below. Each source keeps its own terms, reproduced here as those terms require. The MIT License in
[LICENSE](LICENSE) covers only this project's own code, rules and inferred mappings.

What is included from each source:

- **MITRE CWE:** weakness ids, names, abstraction, status, mapping-usage notes, alternate terms and related CAPEC ids.
  The rule-derived links are computed from CWE mitigation and detection fields; that text itself is not included.
- **MITRE CAPEC:** attack pattern ids, names, abstraction, status, severity, related CWE ids and ATT&CK ids.
- **MITRE ATT&CK:** technique ids and names.
- **MITRE Center for Threat-Informed Defense, Mappings Explorer:** ATT&CK technique → NIST SP 800-53 Rev 5 links,
  converted to per-technique control lists.
- **NIST SP 800-53 Rev 5** (via usnistgov/oscal-content): control ids and titles.
- **NIST SP 800-218 (SSDF) v1.1:** practice and task ids and text, and the SSDF's references to SP 800-53.

---

## Common Weakness Enumeration (CWE™)

Copyright © 2006–2026, The MITRE Corporation. CWE, CWSS, CWRAF, and the CWE logo are trademarks of The MITRE Corporation.

Source: https://cwe.mitre.org/ · Terms of Use: https://cwe.mitre.org/about/termsofuse.html

> CWE™ is free to use by any organization or individual for any research, development, and/or commercial purposes,
> per these CWE Terms of Use. Accordingly, The MITRE Corporation hereby grants you a non-exclusive, royalty-free
> license to use CWE for research, development, and commercial purposes. Any copy you make for such purposes is
> authorized on the condition that you reproduce MITRE’s copyright designation and this license in any such copy.
> CWE is a trademark of The MITRE Corporation. Please contact cwe@mitre.org if you require further clarification on
> this issue.
>
> DISCLAIMERS
>
> By accessing information through this site you (as “the user”) hereby agrees the site and the information is
> provided on an “as is” basis only without warranty of any kind, express or implied, including but not limited to
> implied warranties of merchantability, availability, accuracy, noninfringement, or fitness for a particular purpose.
> Use of this site and the information is at the user’s own risk. The user shall comply with all applicable laws,
> rules, and regulations, and the data source’s restrictions, when using the site.
>
> By contributing information to this site you (as “the contributor”) hereby represents and warrants the contributor
> has obtained all necessary permissions from copyright holders and other third parties to allow the contributor to
> contribute, and this site to host and display, the information and any such contribution, hosting, and displaying
> will not violate any law, rule, or regulation. Additionally, the contributor hereby grants all users of such
> information a perpetual, worldwide, non-exclusive, no-charge, royalty-free, irrevocable license to reproduce,
> prepare derivative works of, publicly display, publicly perform, sublicense, and distribute such information and
> all derivative works.
>
> The MITRE Corporation expressly disclaims any liability for any damages arising from the contributor’s contribution
> of such information, the user’s use of the site or such information, and The MITRE Corporation’s hosting the tool
> and displaying the information. The foregoing disclaimer specifically includes but is not limited to general,
> consequential, indirect, incidental, exemplary, or special or punitive damages (including but not limited to loss of
> income, program interruption, loss of information, or other pecuniary loss) arising out of use of this information,
> no matter the cause of action, even if The MITRE Corporation has been advised of the possibility of such damages.

## Common Attack Pattern Enumeration and Classification (CAPEC™)

Copyright © 2007–2026, The MITRE Corporation. CAPEC and the CAPEC logo are trademarks of The MITRE Corporation.

Source: https://capec.mitre.org/ · Terms of Use: https://capec.mitre.org/about/termsofuse.html

> LICENSE
>
> The MITRE Corporation (MITRE) hereby grants you a non-exclusive, royalty-free license to use Common Attack Pattern
> Enumeration and Classification (CAPEC™) for research, development, and commercial purposes. Any copy you make for
> such purposes is authorized provided that you reproduce MITRE’s copyright designation and this license in any such
> copy.
>
> DISCLAIMERS
>
> ALL DOCUMENTS AND THE INFORMATION CONTAINED THEREIN ARE PROVIDED ON AN "AS IS" BASIS AND THE CONTRIBUTOR, THE
> ORGANIZATION HE/SHE REPRESENTS OR IS SPONSORED BY (IF ANY), THE MITRE CORPORATION, ITS BOARD OF TRUSTEES, OFFICERS,
> AGENTS, AND EMPLOYEES, DISCLAIM ALL WARRANTIES, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO ANY WARRANTY THAT
> THE USE OF THE INFORMATION THEREIN WILL NOT INFRINGE ANY RIGHTS OR ANY IMPLIED WARRANTIES OF MERCHANTABILITY OR
> FITNESS FOR A PARTICULAR PURPOSE.

## MITRE ATT&CK®

© 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation.
MITRE ATT&CK and ATT&CK are registered trademarks of The MITRE Corporation.

Source: https://attack.mitre.org/ · Terms of Use: https://attack.mitre.org/resources/legal-and-branding/terms-of-use/

> LICENSE
>
> The MITRE Corporation (MITRE) hereby grants you a non-exclusive, royalty-free license to use ATT&CK® for research,
> development, and commercial purposes. Any copy you make for such purposes is authorized provided that you reproduce
> MITRE's copyright designation and this license in any such copy.
>
> "© 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE
> Corporation."
>
> DISCLAIMERS
>
> MITRE does not claim ATT&CK enumerates all possibilities for the types of actions and behaviors documented as part
> of its adversary model and framework of techniques. Using the information contained within ATT&CK to address or
> cover full categories of techniques will not guarantee full defensive coverage as there may be undisclosed
> techniques or variations on existing techniques not documented by ATT&CK.
>
> ALL DOCUMENTS AND THE INFORMATION CONTAINED THEREIN ARE PROVIDED ON AN "AS IS" BASIS AND THE CONTRIBUTOR, THE
> ORGANIZATION HE/SHE REPRESENTS OR IS SPONSORED BY (IF ANY), THE MITRE CORPORATION, ITS BOARD OF TRUSTEES, OFFICERS,
> AGENTS, AND EMPLOYEES, DISCLAIM ALL WARRANTIES, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO ANY WARRANTY THAT
> THE USE OF THE INFORMATION THEREIN WILL NOT INFRINGE ANY RIGHTS OR ANY IMPLIED WARRANTIES OF MERCHANTABILITY OR
> FITNESS FOR A PARTICULAR PURPOSE.

## Mappings Explorer (MITRE Center for Threat-Informed Defense)

© 2024 MITRE. Approved for public release. Document number(s) CT0104.

Source: https://github.com/center-for-threat-informed-defense/mappings-explorer (ATT&CK 16.1 ↔ NIST SP 800-53 Rev 5
mappings). Licensed under the Apache License, Version 2.0; a copy is in [licenses/Apache-2.0.txt](licenses/Apache-2.0.txt).
Modification notice: this project converted the published mapping files into per-technique lists of SP 800-53
control ids (`data/att/`) and dropped the other fields.

## NIST SP 800-53 Rev 5 and NIST SP 800-218 (SSDF) v1.1

Sources: https://github.com/usnistgov/oscal-content (SP 800-53 Rev 5 catalog) and
https://csrc.nist.gov/pubs/sp/800/218/final (SSDF 1.1 table).

The oscal-content repository states: "This project is in the worldwide public domain". "As a work of the United
States government, this project is in the public domain within the United States." "Additionally, we waive copyright
and related rights in the work worldwide through the CC0 1.0 Universal public domain dedication."

SP 800-218 is a publication of the U.S. National Institute of Standards and Technology, a work of the U.S. Government.
NIST does not endorse this project.
