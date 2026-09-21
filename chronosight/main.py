#!/usr/bin/env python3
"""
ChronoSight — AI-Powered Digital Artifact Timeline Extractor.

CLI entry point.  Parses command-line arguments, orchestrates the
forensic extraction pipeline, and optionally invokes the Gemini AI
analyzer.

Usage examples:
    chronosight -t /var/log
    chronosight --target /home/user/Downloads --api-key AIza...
    chronosight -t /tmp --output report.json --no-ai
    GEMINI_API_KEY=AIza... chronosight -t /etc
"""

import argparse
import json
import os
import sys
import time
from pathlib import Path

from chronosight import __version__
from chronosight.extractor import scan_directory
from chronosight.timeline import build_timeline, export_timeline, timeline_summary
from chronosight.analyzer import analyze_timeline
from chronosight.ui import (
    console,
    print_banner,
    print_artifact_table,
    print_error,
    print_info,
    print_scan_summary_table,
    print_status,
    print_success,
    print_warning,
)


# ---------------------------------------------------------------------------
# CLI Argument Parser
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    """
    Construct the argument parser for ChronoSight.

    Returns:
        Configured :class:`argparse.ArgumentParser`.
    """
    parser = argparse.ArgumentParser(
        prog="chronosight",
        description=(
            "ChronoSight — AI-Powered Digital Artifact Timeline Extractor.\n"
            "Scans a target directory, extracts forensic MAC timestamps and "
            "file hashes, builds a chronological timeline, and optionally "
            "analyses it with Google Gemini AI to detect anomalies."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  chronosight -t /var/log\n"
            "  chronosight -t /home/user/Downloads -k AIza...\n"
            "  chronosight -t /tmp -o report.json --no-ai\n"
            "  GEMINI_API_KEY=AIza... chronosight -t /etc\n"
        ),
    )

    parser.add_argument(
        "-t", "--target",
        type=str,
        required=True,
        help="Target directory to scan for forensic artifacts.",
    )
    parser.add_argument(
        "-k", "--api-key",
        type=str,
        default=None,
        help=(
            "Google Gemini API key.  If omitted, the tool reads the "
            "GEMINI_API_KEY environment variable."
        ),
    )
    parser.add_argument(
        "-o", "--output",
        type=str,
        default=None,
        help=(
            "Path to save the timeline JSON report.  "
            "Defaults to chronosight_timeline.json in the current directory."
        ),
    )
    parser.add_argument(
        "-m", "--model",
        type=str,
        default="gemini-3.6-flash",
        help="Gemini model to use for analysis (default: gemini-3.6-flash).",
    )
    parser.add_argument(
        "--no-ai",
        action="store_true",
        default=False,
        help="Skip AI analysis — only extract and build the timeline.",
    )
    parser.add_argument(
        "--save-analysis",
        type=str,
        default=None,
        help="Path to save the AI analysis report as a Markdown file.",
    )
    parser.add_argument(
        "-v", "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    return parser


# ---------------------------------------------------------------------------
# Main Entry Point
# ---------------------------------------------------------------------------

def main() -> None:
    """
    ChronoSight main execution flow:

    1. Parse CLI arguments
    2. Display banner
    3. Scan target directory → extract forensic metadata
    4. Build chronological timeline
    5. Export timeline to JSON
    6. (Optional) Send to Gemini AI for anomaly analysis
    7. Display results
    """
    parser = build_parser()
    args = parser.parse_args()

    # ── Display banner ──
    print_banner()

    # ── Resolve target ──
    target = Path(args.target).resolve()
    print_status(f"Target directory: [bold]{target}[/bold]")

    # ── Phase 1: Extraction ──
    console.rule("[header]Phase 1 · Forensic Extraction[/header]", style="bright_green")
    start = time.time()
    artifacts = scan_directory(target)
    elapsed = time.time() - start

    if not artifacts:
        print_warning("No files found in the target directory.")
        raise SystemExit(0)

    print_success(f"Extracted metadata for [bold]{len(artifacts)}[/bold] files in {elapsed:.2f}s")
    print_artifact_table(artifacts)

    # ── Phase 2: Timeline Construction ──
    console.rule("[header]Phase 2 · Timeline Construction[/header]", style="bright_green")
    events = build_timeline(artifacts)
    summary = timeline_summary(events)
    print_success(f"Built timeline with [bold]{summary['total_events']}[/bold] events")
    print_scan_summary_table(summary)

    # ── Phase 3: Export ──
    output_path = Path(args.output) if args.output else Path("chronosight_timeline.json")
    exported = export_timeline(events, output_path)
    print_success(f"Timeline saved to [bold]{exported}[/bold]")

    # ── Phase 4: AI Analysis ──
    if args.no_ai:
        print_info("AI analysis skipped (--no-ai flag).")
    else:
        console.rule("[header]Phase 3 · AI Anomaly Analysis[/header]", style="bright_green")

        # Resolve API key: CLI flag > environment variable.
        api_key = args.api_key or os.environ.get("GEMINI_API_KEY")
        if not api_key:
            print_warning(
                "No Gemini API key provided.\n"
                "  Supply one with [cyan]-k / --api-key[/cyan] or set the "
                "[cyan]GEMINI_API_KEY[/cyan] environment variable.\n"
                "  Skipping AI analysis."
            )
        else:
            analysis = analyze_timeline(events, api_key=api_key, model=args.model)

            if analysis and args.save_analysis:
                save_path = Path(args.save_analysis).resolve()
                save_path.parent.mkdir(parents=True, exist_ok=True)
                save_path.write_text(analysis, encoding="utf-8")
                print_success(f"Analysis report saved to [bold]{save_path}[/bold]")

    # ── Done ──
    console.print()
    console.rule("[header]✔ ChronoSight Complete[/header]", style="bright_green")
    console.print()


if __name__ == "__main__":
    main()
