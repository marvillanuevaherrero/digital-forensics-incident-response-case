import json
from pathlib import Path
import pytest
from ircase.core import EvidenceError, correlate, digest, render_markdown, timestamp, verify_manifest
from ircase.cli import main

ROOT = Path(__file__).resolve().parents[1]

def test_case_event_count():
    assert len(correlate(ROOT / "evidence")["events"]) == 9

def test_sources():
    assert correlate(ROOT / "evidence")["counts"] == {"memory": 3, "disk": 3, "network": 3}

def test_ordered():
    times = [e["timestamp"] for e in correlate(ROOT / "evidence")["events"]]
    assert times == sorted(times)

def test_indicators():
    assert "203.0.113.77:443" in correlate(ROOT / "evidence")["indicators"]

def test_integrity():
    assert correlate(ROOT / "evidence")["integrity"]["verified"]

def test_timestamp_requires_timezone():
    with pytest.raises(EvidenceError): timestamp("2026-01-01T00:00:00")

def test_timestamp_normalizes():
    assert timestamp("2026-01-01T01:00:00+01:00").isoformat() == "2026-01-01T00:00:00+00:00"

def test_tamper_detection(tmp_path):
    for filename in ("memory.json", "disk.json", "network.json", "manifest.json"):
        (tmp_path / filename).write_bytes((ROOT / "evidence" / filename).read_bytes())
    (tmp_path / "disk.json").write_text("[]")
    with pytest.raises(EvidenceError, match="Hash mismatch"): correlate(tmp_path)

def test_traversal_rejected():
    with pytest.raises(EvidenceError, match="paths"):
        verify_manifest(ROOT / "evidence", {"files": [{"path": "../secrets", "sha256": "x"}]})

def test_duplicate_ids(tmp_path):
    import shutil
    for filename in ("memory.json", "disk.json", "network.json"):
        shutil.copy(ROOT / "evidence" / filename, tmp_path / filename)
    memory = json.loads((tmp_path / "memory.json").read_text())
    disk = json.loads((tmp_path / "disk.json").read_text())
    disk[0]["event_id"] = memory[0]["event_id"]
    (tmp_path / "disk.json").write_text(json.dumps(disk))
    files = [{"path": n, "sha256": digest(tmp_path / n)} for n in ("memory.json", "disk.json", "network.json")]
    (tmp_path / "manifest.json").write_text(json.dumps({"files": files}))
    with pytest.raises(EvidenceError, match="Duplicate event ID"): correlate(tmp_path)

def test_report_author():
    assert render_markdown(correlate(ROOT / "evidence")).rstrip().endswith("Por Mar Villanueva Herrero")

def test_cli(tmp_path):
    assert main(["--evidence", str(ROOT / "evidence"), "--output", str(tmp_path)]) == 0
    assert (tmp_path / "report.md").exists()
    assert (tmp_path / "timeline.json").exists()
