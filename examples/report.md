# Investigation report — IR-2026-017

**Evidence classification:** SYNTHETIC TRAINING DATA. No real memory image, disk image or PCAP was acquired.

## Integrity

All manifest-listed evidence files passed SHA-256 verification.

## Timeline (UTC)

| Time | Source | Activity | Evidence |
|---|---|---|---|
| 2026-02-18T09:12:03Z | memory | process_start — Office process spawned PowerShell with encoded command-line argument (synthetic). | MEM-001/process-tree |
| 2026-02-18T09:12:11Z | disk | file_create — Script file created in user temporary directory (synthetic). | DSK-001/file-metadata |
| 2026-02-18T09:12:18Z | memory | process_start — PowerShell child process launched a scripting runtime (synthetic). | MEM-002/process-tree |
| 2026-02-18T09:13:03Z | network | dns_query — DNS request for lab-only example domain. | NET-001/dns-log |
| 2026-02-18T09:14:42Z | disk | archive_create — Archive containing test documents created under user profile. | DSK-002/file-metadata |
| 2026-02-18T09:18:02Z | memory | network_socket — Scripting process observed with outbound TCP socket to documentation-range address. | MEM-003/socket-table |
| 2026-02-18T09:18:03Z | network | tls_flow — Outbound TLS flow to documentation-range IP; payload unavailable. | NET-002/flow-log |
| 2026-02-18T09:18:26Z | network | egress_volume — Outbound transfer volume exceeded workstation baseline in synthetic flow summary. | NET-003/flow-log |
| 2026-02-18T09:19:10Z | disk | file_delete — Temporary script removed after network activity. | DSK-003/file-metadata |

## Indicators (training-only)

- `-EncodedCommand`
- `203.0.113.77:443`
- `C:\Users\analyst\AppData\Local\Temp\bundle.zip`
- `C:\Users\analyst\AppData\Local\Temp\stage.vbs`
- `powershell.exe`
- `stage.vbs`
- `telemetry.example`
- `wscript.exe`

## Assessment

The combined synthetic artifacts support a **probable scripted execution, staged collection and outbound transfer** hypothesis. The precise initial access vector and whether data was received by a remote party cannot be established from this evidence alone.

## Scope and limitations

Memory entries are curated process/network observations, not Volatility output from a RAM dump. Disk entries are curated file/registry observations, not a forensic disk image. Network entries are curated flow records, not packet captures. This report demonstrates evidence correlation, not forensic acquisition or malware attribution.

## Recommended response

Preserve original evidence, validate host telemetry and process lineage, review relevant authentication logs, investigate outbound traffic in authorized systems, and rotate potentially exposed credentials following incident-response policy.

Por Mar Villanueva Herrero
