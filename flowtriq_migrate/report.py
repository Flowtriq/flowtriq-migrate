"""Format migration report for terminal output."""

from __future__ import annotations

import sys
from typing import Any, Dict, List, Optional


def _supports_unicode() -> bool:
    """Check if stdout supports Unicode box-drawing characters."""
    try:
        enc = getattr(sys.stdout, "encoding", "") or ""
        return "utf" in enc.lower()
    except Exception:
        return False


def format_report(
    parsed: Dict[str, Any],
    flowtriq_config: Dict[str, Any],
    notes: List[Dict[str, str]],
    source_path: str,
    output_path: Optional[str] = None,
) -> str:
    """Build the migration report string."""
    use_unicode = _supports_unicode()

    if use_unicode:
        bar = "\u2550" * 60
        check = "\u2713"
        arrow = "\u2192"
        warn = "\u26a0"
        bolt = "\u26a1"
        bullet = "\u2022"
    else:
        bar = "=" * 60
        check = "+"
        arrow = "->"
        warn = "!"
        bolt = "*"
        bullet = "-"

    edition = parsed.get("edition", "unknown")
    edition_labels = {
        "community": "FastNetMon Community",
        "advanced": "FastNetMon Advanced",
        "wanguard": "Wanguard (Andrisoft)",
        "corero": "Corero SmartWall",
    }
    edition_label = edition_labels.get(edition, edition.title())
    lines = [
        "",
        bar,
        "  Flowtriq Migration Report",
        f"  Source: {source_path} ({edition_label})",
        bar,
        "",
    ]

    # Mapped settings
    mapped = [n for n in notes if n["type"] == "mapped"]
    if mapped:
        lines.append(f"  {check} MAPPED SETTINGS")
        for note in mapped:
            for i, line in enumerate(note["message"].split("\n")):
                prefix = "    " if i == 0 else "      "
                lines.append(f"{prefix}{line}")
        lines.append("")

    # Manual steps
    manual = [n for n in notes if n["type"] == "manual"]
    if manual:
        lines.append(f"  {warn} MANUAL STEPS REQUIRED")
        # Always lead with the API key step
        lines.append(
            f"    1. Get your API key and Node UUID from "
            f"https://flowtriq.com/dashboard"
        )
        lines.append(
            f"       Update {output_path or 'config.json'} with your credentials."
        )
        for i, note in enumerate(manual, start=2):
            for j, line in enumerate(note["message"].split("\n")):
                if j == 0:
                    lines.append(f"    {i}. {line}")
                else:
                    lines.append(f"       {line}")
        lines.append("")

    # Info notes
    info = [n for n in notes if n["type"] == "info"]
    if info:
        lines.append(f"  {bolt} NOTES")
        for note in info:
            for i, line in enumerate(note["message"].split("\n")):
                prefix = f"    {bullet} " if i == 0 else "      "
                lines.append(f"{prefix}{line}")
        lines.append("")

    # New in Flowtriq
    lines.append(f"  {bolt} NEW IN FLOWTRIQ (advantages over {edition_label})")
    gains = [
        "Sub-second attack detection (vs 30-60s with flow sampling)",
        "L7 application-layer DDoS detection (HTTP floods, DNS amplification)",
        "Per-packet PCAP forensics with automatic pre-attack capture",
        "Adaptive baseline learning (no manual threshold tuning)",
        "Real-time dashboard with attack timelines and drill-down",
        "Alerts wherever your NOC works (Slack, PagerDuty, Discord, SMS, and more)",
        "XDP/eBPF kernel-level filtering for line-rate mitigation",
        "Service port awareness (block attack traffic, keep legitimate ports open)",
    ]
    for g in gains:
        lines.append(f"    {bullet} {g}")
    lines.append("")

    # Footer
    if output_path:
        lines.append(f"  Config written to: {output_path}")
        lines.append(
            f"  Next: curl -sSL https://flowtriq.com/install.sh | sudo bash"
        )
    lines.append("")

    return "\n".join(lines)
