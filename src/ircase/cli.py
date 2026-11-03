"""Command line entry point."""
import argparse
import json
import sys
from pathlib import Path
from .core import EvidenceError, correlate, render_markdown

def main(argv=None):
    parser = argparse.ArgumentParser(description="Offline synthetic DFIR evidence correlation")
    parser.add_argument("--evidence", type=Path, default=Path("evidence"))
    parser.add_argument("--output", type=Path, default=Path("output"))
    args = parser.parse_args(argv)
    try:
        result = correlate(args.evidence)
        args.output.mkdir(parents=True, exist_ok=True)
        (args.output / "timeline.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        (args.output / "report.md").write_text(render_markdown(result), encoding="utf-8")
        print(f"Verified {len(result['integrity']['files'])} evidence files; correlated {len(result['events'])} events")
        return 0
    except (EvidenceError, OSError) as exc:
        print(f"Evidence processing failed: {exc}", file=sys.stderr)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
