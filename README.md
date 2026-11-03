# Incident Forensics — End-to-End DFIR Case Study

A reproducible, **synthetic** digital forensics and incident response (DFIR) investigation that correlates memory-derived observations, disk artifacts and network metadata into a single UTC timeline. The repository is designed to demonstrate analytical rigor, evidence integrity checking, provenance awareness and defensible incident reporting.

> **Scope:** This repository does not ship a RAM dump, forensic disk image or PCAP. All supplied observations are fictional JSON fixtures. It does not claim to perform raw memory or disk acquisition.

## Investigation scenario

Case **IR-2026-017** concerns a fictional Windows workstation (`WS-17`) exhibiting a suspicious process chain, temporary script and archive creation, and outbound network activity. The task is to determine what the available evidence supports and what remains unproven.

## Capabilities

- SHA-256 verification of the three evidence fixture files against a manifest before analysis
- Schema validation, duplicate-ID rejection and timezone-aware timestamp normalization
- Chronological correlation across **memory**, **disk** and **network** observations
- Machine-readable JSON timeline and Markdown investigation report
- A documented investigative hypothesis with explicit uncertainty and limitations
- Automated tests for integrity, ordering, UTC conversion, input validation and CLI output
- CI workflow to run tests and lint checks

## Architecture

```text
Synthetic evidence (memory.json / disk.json / network.json)
        |                 manifest.json (SHA-256)
        +------------------------+
                                 v
                     Integrity verification
                                 v
                     Validation and UTC normalization
                                 v
                     Cross-source timeline correlation
                                 v
                        timeline.json + report.md
```

## Repository layout

```text
src/ircase/                Python CLI and analysis engine
evidence/                  Synthetic fixtures and SHA-256 manifest
tests/                     Automated regression tests
docs/CASE_BRIEF.md         Incident narrative and evidence assessment
docs/ACQUISITION_PLAYBOOK.md  Real-lab collection methodology
docs/METHODOLOGY.md        Forensic reasoning and limitations
docs/CHAIN_OF_CUSTODY_TEMPLATE.csv  Custody log template
.github/workflows/ci.yml  Continuous integration
```

## Quick start

Requires Python 3.10+; no runtime third-party dependencies.

```bash
python -m venv .venv
# Windows PowerShell: .\.venv\Scripts\Activate.ps1
# Linux/macOS: source .venv/bin/activate
python -m pip install -e '.[dev]'
python -m ircase --evidence evidence --output output
python -m pytest -q
```

Generated outputs:

- `output/timeline.json`: verified hashes, source counts, normalized events and training indicators
- `output/report.md`: chronology, assessment, limitations and next actions

## Example timeline (UTC)

| Time | Evidence | Observation |
|---|---|---|
| 09:12:03 | Memory | Office application spawns PowerShell |
| 09:12:11 | Disk | Temporary script created |
| 09:14:42 | Disk | Archive created |
| 09:18:03 | Network | Outbound TLS flow |
| 09:18:26 | Network | Elevated outbound volume |

**Assessment:** the artifacts are consistent with possible script-driven collection and outbound transfer. They do **not** prove malicious intent, packet payload contents or successful exfiltration.

## Reproduce an integrity failure

Copy `evidence/` to a temporary directory, change one byte in `disk.json` without updating the manifest and run the CLI against that copy. The program refuses to analyze the tampered input and exits with status 2.

## Security and privacy

All IP addresses use RFC 5737 documentation ranges; the example domain is non-operational. Do not add actual credentials, personal information, private incident artifacts or proprietary images to the repository. Analyze real evidence only with proper authorization and chain-of-custody controls.

## Limitations

The memory, disk and network datasets are curated training records, not raw forensic captures. This project does not parse memory images, NTFS disk images, EVTX or PCAP, and its SHA-256 manifest is not a signed acquisition record. No malware was executed and no real system was investigated. Consult `docs/ACQUISITION_PLAYBOOK.md` for a path toward a genuine acquisition-based laboratory.

## License

MIT. See `LICENSE`.

## Author

Por Mar Villanueva Herrero
