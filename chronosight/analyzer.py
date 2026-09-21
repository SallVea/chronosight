"""
AI Analyzer Module — Gemini Integration.

Sends the forensic timeline to Google Gemini and receives an expert
analysis of potential anomalies such as timestamp manipulation,
data exfiltration patterns, and malware staging indicators.

Uses the modern ``google-genai`` SDK (>= 2.3.0).
"""

import json
import sys
from typing import Any

from rich.markdown import Markdown
from rich.panel import Panel

from chronosight.ui import console, print_error, print_info, print_status

# ---------------------------------------------------------------------------
# System Prompt — Forensic Analyst Persona
# ---------------------------------------------------------------------------

FORENSIC_SYSTEM_PROMPT = """\
You are **ChronoSight AI**, an elite digital forensics investigator with \
20+ years of experience in incident response and threat hunting.

You will receive a JSON timeline of file-system events extracted from a \
Linux host.  Each event contains:
  - timestamp (ISO-8601 UTC)
  - event_type (MODIFIED / ACCESSED / CREATED)
  - path (absolute file path)
  - size_bytes
  - file_type
  - md5 / sha256 hashes

Your mission:

1. **Anomaly Detection** — Identify suspicious patterns:
   • Clusters of file modifications outside business hours (00:00–05:00 local)
   • Rapid sequential access to many files (possible enumeration / exfiltration)
   • Timestamp inconsistencies (e.g., created > modified — clock tampering)
   • Unusual file extensions or paths (e.g., files in /tmp, /dev/shm, dotfiles)
   • Duplicate hashes across different paths (possible staging or lateral movement)
   • Abnormally large files in sensitive directories

2. **Threat Classification** — For each finding, assign a severity:
   • 🔴 CRITICAL — Active compromise or data exfiltration evidence
   • 🟠 HIGH — Strong indicators of malicious activity
   • 🟡 MEDIUM — Suspicious but could be benign
   • 🟢 LOW — Informational, worth noting

3. **Actionable Recommendations** — Suggest concrete next steps:
   • Which files to quarantine or acquire for deeper analysis
   • Additional log sources to correlate (auth.log, syslog, network captures)
   • Containment actions if compromise is confirmed

4. **Output Format** — Structure your response with clear Markdown:
   • Executive summary (2–3 sentences)
   • Detailed findings table
   • Risk score (0–100)
   • Recommendations

Be precise.  Do not hallucinate file paths or hashes that are not in the \
provided data.  If the timeline appears benign, state that clearly with \
your confidence level.
"""


# ---------------------------------------------------------------------------
# Core: Analyse Timeline with Gemini
# ---------------------------------------------------------------------------

def analyze_timeline(
    events: list[dict[str, Any]],
    api_key: str,
    model: str = "gemini-3.6-flash",
) -> str | None:
    """
    Send the forensic timeline to Gemini for AI-powered anomaly analysis.

    The function constructs a prompt containing the system instruction
    (forensic persona) and the full timeline JSON, then streams the
    response back to the terminal for real-time feedback.

    Args:
        events:  Chronologically sorted timeline events.
        api_key: Google Gemini API key.
        model:   Gemini model identifier (default: ``gemini-3.6-flash``).

    Returns:
        The complete analysis text, or ``None`` on failure.
    """
    # ── Lazy-import to avoid hard crash if the SDK is missing ──
    try:
        from google import genai
        from google.genai import types
    except ImportError:
        print_error(
            "The [bold]google-genai[/bold] package is not installed.\n"
            "Install it with: [cyan]pip install google-genai[/cyan]"
        )
        return None

    # ── Initialise the Gemini client ──
    try:
        client = genai.Client(api_key=api_key)
    except Exception as exc:
        print_error(f"Failed to initialise Gemini client: {exc}")
        return None

    # ── Prepare the timeline payload ──
    # Truncate to the most recent 500 events if the timeline is very large
    # to stay within model context limits and reduce token costs.
    max_events = 500
    if len(events) > max_events:
        print_info(
            f"Timeline contains {len(events)} events — "
            f"sending the most recent {max_events} to the AI."
        )
        payload_events = events[-max_events:]
    else:
        payload_events = events

    timeline_json = json.dumps(payload_events, indent=2, ensure_ascii=False)

    user_prompt = (
        "Analyse the following forensic file-system timeline and identify "
        "any anomalies, indicators of compromise, or suspicious patterns.\n\n"
        f"```json\n{timeline_json}\n```"
    )

    # ── Call the Gemini API ──
    print_status(f"Transmitting timeline to Gemini AI ({model}) for analysis…")

    afc_config = types.AutomaticFunctionCallingConfig(disable=True)
    gen_config = types.GenerateContentConfig(
        system_instruction=FORENSIC_SYSTEM_PROMPT,
        temperature=0.2,   # Low temperature for analytical precision
        max_output_tokens=8192,
        automatic_function_calling=afc_config,
    )

    candidate_models = [model]
    for fallback in ("gemini-3.6-flash", "gemini-3.8-flash", "gemini-flash-latest"):
        if fallback not in candidate_models:
            candidate_models.append(fallback)

    response = None
    last_exc = None

    for active_model in candidate_models:
        try:
            response = client.models.generate_content(
                model=active_model,
                contents=user_prompt,
                config=gen_config,
            )
            break
        except Exception as exc:
            last_exc = exc
            error_msg = str(exc)
            if "NOT_FOUND" in error_msg or "404" in error_msg or "no longer available" in error_msg:
                # Try next model in candidate_models
                continue
            elif "PERMISSION_DENIED" in error_msg or "API_KEY_INVALID" in error_msg:
                print_error(
                    "Invalid API key or permission denied.  "
                    "Verify your Gemini API key at https://aistudio.google.com/apikey"
                )
                return None
            elif "RESOURCE_EXHAUSTED" in error_msg or "429" in error_msg:
                print_error(
                    "API rate limit exceeded.  Wait a moment and try again, "
                    "or upgrade your Gemini API plan."
                )
                return None
            elif "DEADLINE_EXCEEDED" in error_msg or "timeout" in error_msg.lower():
                print_error(
                    "Request to Gemini timed out.  The timeline may be too large — "
                    "try scanning a smaller directory."
                )
                return None
            else:
                print_error(f"Gemini API error: {exc}")
                return None

    if response is None:
        print_error(f"Gemini API error: {last_exc}")
        return None

    # ── Extract the text response ──
    try:
        analysis_text = response.text
    except (AttributeError, ValueError):
        # Some models may return candidates differently.
        try:
            analysis_text = response.candidates[0].content.parts[0].text
        except Exception:
            print_error("Received an empty or unparseable response from Gemini.")
            return None

    if not analysis_text:
        print_error("Gemini returned an empty response.")
        return None

    # ── Display the analysis ──
    console.print()
    console.print(
        Panel(
            Markdown(analysis_text),
            title="[bold red]⚡ ChronoSight AI Analysis ⚡[/bold red]",
            border_style="red",
            padding=(1, 2),
        )
    )

    return analysis_text
