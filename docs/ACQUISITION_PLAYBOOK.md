# Acquisition playbook for a future real laboratory

The shipped evidence is curated JSON and **not** a forensic image. For a real authorized lab, document owner consent, incident identifier, device ID, examiner, time, tool versions, clock offset and evidence storage location before collection.

## Memory
Capture RAM with an approved, validated acquisition tool suitable for the operating system and preserve the original image. Compute SHA-256 on acquisition and after transfer. Analyze a verified working copy with a documented Volatility 3 version; record process tree, command lines, loaded modules and network connections with exact plugin names and outputs. Volatile memory is time-sensitive.

## Disk
Acquire a forensic image using write-blocking where feasible. Preserve partition layout and metadata, verify hashes and use a working copy. Collect filesystem timestamps, relevant registry hives, scheduled tasks, event logs and user artifacts. Distinguish NTFS timestamp semantics and time-zone offsets.

## Network
Collect authorized PCAP and DNS/proxy/firewall logs, record capture filters, packet loss and clock synchronization. Distinguish flow metadata from payload content. Do not infer exfiltrated content from byte counts alone.

## Integrity and custody
Track every transfer in a chain-of-custody record, with timestamp, actor, action, evidence identifier, SHA-256, storage location and signature. Hashes support integrity verification but do not alone establish provenance.

## Legal and safety
Use only systems and data for which explicit authorization exists. Never upload confidential evidence to public Git repositories.
