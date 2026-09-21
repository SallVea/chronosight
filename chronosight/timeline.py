"""
Timeline Builder Module.

Takes raw artifact data from the extractor and organises it into a
chronologically sorted timeline.  Each event in the timeline corresponds
to a single MAC timestamp event (file modified, accessed, or created)
linked back to the originating artifact.  The resulting structure is
designed for both human review and AI consumption.
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# Timeline Event Construction
# ---------------------------------------------------------------------------

def _make_event(artifact: dict[str, Any], event_type: str, iso_ts: str) -> dict[str, Any]:
    """
    Create a single timeline event dictionary.

    Args:
        artifact:   The full artifact dict from the extractor.
        event_type: One of ``"MODIFIED"``, ``"ACCESSED"``, ``"CREATED"``.
        iso_ts:     ISO-8601 timestamp string for this event.

    Returns:
        A flat dictionary suitable for chronological sorting.
    """
    return {
        "timestamp": iso_ts,
        "event_type": event_type,
        "path": artifact["path"],
        "size_bytes": artifact["size_bytes"],
        "file_type": artifact["type"],
        "md5": artifact["hashes"]["md5"],
        "sha256": artifact["hashes"]["sha256"],
    }


# ---------------------------------------------------------------------------
# Core: Build Sorted Timeline
# ---------------------------------------------------------------------------

def build_timeline(artifacts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Expand every artifact into three timeline events (one per MAC
    timestamp) and return them sorted in ascending chronological order.

    Sorting is performed on the ISO-8601 timestamp string, which is
    lexicographically sortable because it uses zero-padded UTC format
    (``YYYY-MM-DDTHH:MM:SS+00:00``).

    Args:
        artifacts: List of artifact dicts produced by
                   :func:`chronosight.extractor.scan_directory`.

    Returns:
        A chronologically ordered list of timeline event dicts.
    """
    events: list[dict[str, Any]] = []

    for artifact in artifacts:
        ts = artifact["timestamps"]
        events.append(_make_event(artifact, "MODIFIED", ts["modified"]))
        events.append(_make_event(artifact, "ACCESSED", ts["accessed"]))
        events.append(_make_event(artifact, "CREATED", ts["created"]))

    # Stable sort by ISO-8601 timestamp (lexicographic == chronological).
    events.sort(key=lambda e: e["timestamp"])
    return events


# ---------------------------------------------------------------------------
# Export: Write Timeline to JSON
# ---------------------------------------------------------------------------

def export_timeline(events: list[dict[str, Any]], output_path: Path) -> Path:
    """
    Serialise the timeline to a JSON file on disk.

    Args:
        events:      The sorted list of timeline events.
        output_path: Destination file path (will be overwritten).

    Returns:
        The resolved ``Path`` of the written file.
    """
    output_path = output_path.resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(
            {"event_count": len(events), "timeline": events},
            fh,
            indent=2,
            ensure_ascii=False,
        )

    return output_path


# ---------------------------------------------------------------------------
# Summary Statistics
# ---------------------------------------------------------------------------

def timeline_summary(events: list[dict[str, Any]]) -> dict[str, Any]:
    """
    Compute quick summary statistics for display in the CLI.

    Returns:
        Dict with keys: ``total_events``, ``unique_files``,
        ``earliest``, ``latest``, ``event_type_counts``.
    """
    if not events:
        return {
            "total_events": 0,
            "unique_files": 0,
            "earliest": "N/A",
            "latest": "N/A",
            "event_type_counts": {},
        }

    unique = {e["path"] for e in events}
    type_counts: dict[str, int] = {}
    for e in events:
        t = e["event_type"]
        type_counts[t] = type_counts.get(t, 0) + 1

    return {
        "total_events": len(events),
        "unique_files": len(unique),
        "earliest": events[0]["timestamp"],
        "latest": events[-1]["timestamp"],
        "event_type_counts": type_counts,
    }
