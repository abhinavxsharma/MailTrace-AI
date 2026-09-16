"""
MAILTRACE AI - JSON Forensic Case Report Generator.
Serializes machine-readable, deterministic investigation reports.
"""

import json
from pathlib import Path
from typing import Any, Dict, Optional


def generate_json_report(
    report_data: Dict[str, Any],
    output_path: Optional[Path] = None,
) -> str:
    """
    Format report data as pretty-printed JSON and optionally persist to disk.
    """
    json_str = json.dumps(report_data, indent=2, ensure_ascii=False)

    if output_path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json_str, encoding="utf-8")

    return json_str
