"""Offline correlation of synthetic forensic artifacts. No host collection occurs."""
from __future__ import annotations
from collections import Counter
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from typing import Any
import json

SOURCES = ("memory", "disk", "network")
REQUIRED = {"event_id", "timestamp", "host", "activity", "description", "source_ref"}

class EvidenceError(ValueError):
    """Evidence or schema validation failure."""

def digest(path: Path) -> str:
    h = sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()

def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise EvidenceError(f"Cannot read evidence {path.name}: {exc}") from exc

def timestamp(value: str) -> datetime:
    if not isinstance(value, str):
        raise EvidenceError("timestamp must be an ISO 8601 string")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise EvidenceError(f"Invalid timestamp: {value}") from exc
    if parsed.tzinfo is None:
        raise EvidenceError("Timestamps must include a UTC offset")
    return parsed.astimezone(timezone.utc)

def verify_manifest(folder: Path, manifest: dict) -> dict:
    entries = manifest.get("files")
    if not isinstance(entries, list) or not entries:
        raise EvidenceError("Manifest must contain nonempty files list")
    checked = []
    seen = set()
    for item in entries:
        if not isinstance(item, dict) or not isinstance(item.get("path"), str):
            raise EvidenceError("Invalid manifest entry")
        rel = Path(item["path"])
        if rel.is_absolute() or ".." in rel.parts or len(rel.parts) != 1:
            raise EvidenceError("Manifest paths must be evidence filenames")
        if rel.name in seen:
            raise EvidenceError("Duplicate manifest entry")
        seen.add(rel.name)
        path = folder / rel
        if not path.is_file() or path.is_symlink():
            raise EvidenceError(f"Missing or unsafe evidence: {rel}")
        actual = digest(path)
        if actual != item.get("sha256"):
            raise EvidenceError(f"Hash mismatch: {rel}")
        checked.append({"path": rel.name, "sha256": actual, "verified": True})
    return {"files": checked, "verified": True}

def correlate(folder: Path) -> dict:
    manifest = load_json(folder / "manifest.json")
    integrity = verify_manifest(folder, manifest)
    events = []
    ids = set()
    for source in SOURCES:
        path = folder / f"{source}.json"
        if path.name not in {f["path"] for f in integrity["files"]}:
            raise EvidenceError(f"Unmanifested source: {path.name}")
        records = load_json(path)
        if not isinstance(records, list):
            raise EvidenceError(f"{source} must contain an array")
        for event in records:
            if not isinstance(event, dict) or not REQUIRED.issubset(event):
                raise EvidenceError(f"Invalid event schema in {source}")
            if not all(isinstance(event[k], str) and event[k] for k in REQUIRED):
                raise EvidenceError(f"Invalid event field in {source}")
            if event["event_id"] in ids:
                raise EvidenceError("Duplicate event ID")
            ids.add(event["event_id"])
            normalized = dict(event)
            normalized["source"] = source
            normalized["timestamp"] = timestamp(event["timestamp"]).isoformat().replace("+00:00", "Z")
            events.append(normalized)
    events.sort(key=lambda e: (e["timestamp"], e["event_id"]))
    indicators = sorted({str(x) for e in events for x in e.get("indicators", [])})
    return {"case_id": manifest.get("case_id", "UNKNOWN"), "synthetic": True,
            "integrity": integrity, "events": events, "indicators": indicators,
            "counts": dict(Counter(e["source"] for e in events))}

def render_markdown(result: dict) -> str:
    lines = [f"# Investigation report — {result['case_id']}", "",
             "**Evidence classification:** SYNTHETIC TRAINING DATA. No real memory image, disk image or PCAP was acquired.", "",
             "## Integrity", "", "All manifest-listed evidence files passed SHA-256 verification.", "",
             "## Timeline (UTC)", "",
             "| Time | Source | Activity | Evidence |", "|---|---|---|---|"]
    for event in result["events"]:
        desc = event["description"].replace("|", "\\|").replace("\n", " ")
        lines.append(f"| {event['timestamp']} | {event['source']} | {event['activity']} — {desc} | {event['source_ref']} |")
    lines += ["", "## Indicators (training-only)", ""]
    lines += [f"- `{indicator}`" for indicator in result["indicators"]]
    lines += ["", "## Assessment", "",
              "The combined synthetic artifacts support a **probable scripted execution, staged collection and outbound transfer** hypothesis. The precise initial access vector and whether data was received by a remote party cannot be established from this evidence alone.", "",
              "## Scope and limitations", "",
              "Memory entries are curated process/network observations, not Volatility output from a RAM dump. Disk entries are curated file/registry observations, not a forensic disk image. Network entries are curated flow records, not packet captures. This report demonstrates evidence correlation, not forensic acquisition or malware attribution.", "",
              "## Recommended response", "",
              "Preserve original evidence, validate host telemetry and process lineage, review relevant authentication logs, investigate outbound traffic in authorized systems, and rotate potentially exposed credentials following incident-response policy.", "",
              "Por Mar Villanueva Herrero", ""]
    return "\n".join(lines)
