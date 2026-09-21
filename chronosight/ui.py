"""
UI / Theme Module — Rich Terminal Output.

Centralises all Rich console configuration, colour themes, and
helper functions for consistent, hacker-themed terminal output
throughout ChronoSight.
"""

from rich.console import Console
from rich.table import Table
from rich.theme import Theme
from rich.panel import Panel
from rich.text import Text
from typing import Any

# ---------------------------------------------------------------------------
# Custom Theme — Cyber / Forensics Aesthetic
# ---------------------------------------------------------------------------

CHRONOSIGHT_THEME = Theme(
    {
        "info": "cyan",
        "warning": "bold yellow",
        "error": "bold red",
        "success": "bold green",
        "highlight": "bold magenta",
        "muted": "dim white",
        "header": "bold bright_green",
        "critical": "bold white on red",
    }
)

# Global console instance used throughout the application.
console = Console(theme=CHRONOSIGHT_THEME)

# ---------------------------------------------------------------------------
# ASCII Banner
# ---------------------------------------------------------------------------

BANNER = r"""[bold bright_green]
   ██████╗██╗  ██╗██████╗  ██████╗ ███╗   ██╗ ██████╗ ███████╗██╗ ██████╗ ██╗  ██╗████████╗
  ██╔════╝██║  ██║██╔══██╗██╔═══██╗████╗  ██║██╔═══██╗██╔════╝██║██╔════╝ ██║  ██║╚══██╔══╝
  ██║     ███████║██████╔╝██║   ██║██╔██╗ ██║██║   ██║███████╗██║██║  ███╗███████║   ██║
  ██║     ██╔══██║██╔══██╗██║   ██║██║╚██╗██║██║   ██║╚════██║██║██║   ██║██╔══██║   ██║
  ╚██████╗██║  ██║██║  ██║╚██████╔╝██║ ╚████║╚██████╔╝███████║██║╚██████╔╝██║  ██║   ██║
   ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝ ╚═════╝ ╚══════╝╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝
[/bold bright_green]
[dim white]        ⟡ AI-Powered Digital Artifact Timeline Extractor ⟡[/dim white]
[dim cyan]                  Forensic Intelligence at Your Fingertips[/dim cyan]
"""


def print_banner() -> None:
    """Display the ChronoSight ASCII banner."""
    console.print(BANNER)


# ---------------------------------------------------------------------------
# Status / Log Helpers
# ---------------------------------------------------------------------------

def print_status(message: str) -> None:
    """Print an informational status message with a ⟐ prefix."""
    console.print(f"  [info]⟐[/info]  {message}")


def print_info(message: str) -> None:
    """Print a general info message with a ℹ prefix."""
    console.print(f"  [info]ℹ[/info]  {message}")


def print_success(message: str) -> None:
    """Print a success message with a ✔ prefix."""
    console.print(f"  [success]✔[/success]  {message}")


def print_warning(message: str) -> None:
    """Print a warning message with a ⚠ prefix."""
    console.print(f"  [warning]⚠[/warning]  {message}")


def print_error(message: str) -> None:
    """Print an error message with a ✘ prefix."""
    console.print(f"  [error]✘[/error]  {message}")


# ---------------------------------------------------------------------------
# Tables
# ---------------------------------------------------------------------------

def print_scan_summary_table(summary: dict[str, Any]) -> None:
    """
    Render a summary table after scanning is complete.

    Args:
        summary: Dict from :func:`chronosight.timeline.timeline_summary`.
    """
    table = Table(
        title="[header]📊 Scan Summary[/header]",
        border_style="bright_green",
        show_header=True,
        header_style="bold cyan",
        padding=(0, 1),
    )
    table.add_column("Metric", style="bold white", min_width=20)
    table.add_column("Value", style="bright_green", justify="right")

    table.add_row("Total Timeline Events", str(summary["total_events"]))
    table.add_row("Unique Files", str(summary["unique_files"]))
    table.add_row("Earliest Event", summary["earliest"])
    table.add_row("Latest Event", summary["latest"])

    for etype, count in summary.get("event_type_counts", {}).items():
        table.add_row(f"  └─ {etype}", str(count))

    console.print()
    console.print(table)
    console.print()


def print_artifact_table(artifacts: list[dict[str, Any]], limit: int = 20) -> None:
    """
    Render a table showing the first *limit* extracted artifacts.

    Args:
        artifacts: List of artifact dicts from the extractor.
        limit:     Maximum rows to display.
    """
    table = Table(
        title="[header]🔍 Extracted Artifacts (Preview)[/header]",
        border_style="bright_green",
        show_header=True,
        header_style="bold cyan",
        padding=(0, 1),
    )
    table.add_column("Path", style="white", max_width=60, no_wrap=True)
    table.add_column("Size", style="bright_yellow", justify="right")
    table.add_column("Modified", style="cyan")
    table.add_column("SHA-256", style="dim white", max_width=16)

    for artifact in artifacts[:limit]:
        size_str = _human_size(artifact["size_bytes"])
        sha_short = artifact["hashes"]["sha256"][:16] + "…"
        table.add_row(
            artifact["path"],
            size_str,
            artifact["timestamps"]["modified"],
            sha_short,
        )

    if len(artifacts) > limit:
        table.add_row(
            f"[muted]… and {len(artifacts) - limit} more files[/muted]",
            "",
            "",
            "",
        )

    console.print()
    console.print(table)
    console.print()


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def _human_size(nbytes: int) -> str:
    """Convert a byte count to a human-readable string (e.g. ``4.2 MiB``)."""
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if abs(nbytes) < 1024:
            return f"{nbytes:.1f} {unit}"
        nbytes /= 1024  # type: ignore[assignment]
    return f"{nbytes:.1f} PiB"
