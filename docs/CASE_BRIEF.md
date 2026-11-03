# Case IR-2026-017 — Suspicious workstation activity

**Classification:** Entirely fictional training case. All timestamps, identities, hosts and telemetry are invented.

## Assignment
Investigate whether workstation `WS-17` shows evidence of suspicious script execution, file staging and outbound communication on 18 February 2026. Preserve a defensible distinction between observation and inference.

## Investigative questions
1. What is the earliest observed suspicious activity?
2. Does the available process lineage connect the scripting activity with a network socket?
3. Is the archive creation temporally consistent with possible collection?
4. Can the analyst prove data exfiltration or identify an initial access vector?

## Findings and confidence
- **Observed in synthetic evidence:** PowerShell execution, child script runtime, temporary script and archive, DNS lookup, TLS flow and elevated egress volume.
- **Reasonable hypothesis (moderate confidence):** script-driven staging followed by outbound transfer.
- **Not established:** execution of malicious code, actual archive contents, TLS payload, external recipient, initial access or adversary identity.

## Suggested ATT&CK hypotheses
- T1059.001 PowerShell (execution hypothesis)
- T1005 Data from Local System (collection hypothesis)
- T1560 Archive Collected Data (collection hypothesis)
- T1041 Exfiltration Over C2 Channel (unconfirmed hypothesis)

Do not treat these technique mappings as verified attack attribution.
