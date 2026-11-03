# Investigation methodology

1. **Scope and triage:** define incident, hypotheses, authorized sources and time bounds.
2. **Preservation:** record acquisition method and SHA-256 manifest; verify before analysis.
3. **Normalization:** convert timestamps to UTC and retain source-specific references.
4. **Correlation:** sort observations and connect only when host, process or indicators justify a relationship.
5. **Evaluation:** separate observed facts, hypotheses, confidence and unanswered questions.
6. **Reporting:** produce a timeline, findings, limitations and next actions.

## Provenance caveat
The JSON `source_ref` values are fictitious pointers for teaching evidence traceability, not offsets into a real image. The manifest is generated at build time and is not a cryptographic signature or trusted third-party attestation.

## Future extensions
Volatility 3 plugin-output import, plaso/log2timeline exports, EVTX parsing, Zeek/Suricata logs, STIX 2.1 export and a structured chain-of-custody database. None is claimed as implemented here.
