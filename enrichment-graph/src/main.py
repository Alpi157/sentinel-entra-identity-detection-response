# enrichment-graph/src/main.py
import json
from pathlib import Path

from investigation_bundle.bundle_builder import IncidentContext, build_investigation_bundle_offline

def main() -> None:
    # This file is: enrichment-graph/src/main.py
    # Project root for this module is: enrichment-graph/
    tool_root = Path(__file__).resolve().parents[1]  # enrichment-graph/
    sample_ctx_path = tool_root / "examples" / "incident_context.sample.json"

    out_dir = tool_root / "sample-output"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "investigation-bundle.sample.json"

    if not sample_ctx_path.exists():
        raise FileNotFoundError(
            f"Missing sample context file:\n  {sample_ctx_path}\n"
            f"Expected it at: enrichment-graph/examples/incident_context.sample.json"
        )

    ctx_raw = json.loads(sample_ctx_path.read_text(encoding="utf-8"))

    ctx = IncidentContext(
        incident_id=ctx_raw["incident_id"],
        title=ctx_raw["title"],
        severity=ctx_raw["severity"],
        time_start=ctx_raw["time_start"],
        time_end=ctx_raw["time_end"],
        detections=ctx_raw.get("detections", []),
        accounts=ctx_raw.get("entities", {}).get("accounts", []),
        ips=ctx_raw.get("entities", {}).get("ips", []),
    )

    bundle = build_investigation_bundle_offline(ctx)
    out_path.write_text(json.dumps(bundle, indent=2), encoding="utf-8")
    print(f"Wrote: {out_path}")

if __name__ == "__main__":
    main()
