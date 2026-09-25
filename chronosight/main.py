#!/usr/bin/env python3
"""
ChronoSight v1.0 — AI-Powered Deep Forensic Artifact & Case Investigator.

Entry point utama dan engine forensik lengkap.

Pipeline Investigasi:
    Fase 1 · Ekstraksi Metadata Mendalam (MAC times, hash, EXIF, PDF, hidden sheet, teks)
    Fase 2 · Pratinjau Artefak di Terminal (tabel Rich)
    Fase 3 · Analisis DFIR oleh Gemini AI (laporan Bahasa Indonesia terstruktur)
    Fase 4 · Ekspor Laporan ke File Markdown (opsional)

Penggunaan:
    chronosight -t /path/ke/artefak
    chronosight -t /mnt/flashdisk -k AIza... -s "Apakah ada data yang diekstrak?"
    chronosight -t /evidence -s skenario.txt -o laporan_dfir.md
    GEMINI_API_KEY=AIza... chronosight -t /artifacts --no-ai

Catatan SDK:
    Menggunakan google-genai >= 2.3.0 (SDK modern).
    google-generativeai (SDK lama) sudah deprecated dan tidak digunakan.
    Model default: gemini-3.6-flash (gemini-1.5-flash sudah deprecated).
"""

# ============================================================
#  IMPORTS
# ============================================================
import argparse
import hashlib
import json
import os
import stat
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table
from rich.theme import Theme

from chronosight import __version__

# ============================================================
#  RICH UI THEME & CONSOLE
# ============================================================

_THEME = Theme({
    "info":      "cyan",
    "warning":   "bold yellow",
    "error":     "bold red",
    "success":   "bold green",
    "header":    "bold bright_green",
    "muted":     "dim white",
    "flag":      "bold red",
})

console = Console(theme=_THEME)

# ============================================================
#  ASCII BANNER
# ============================================================

_BANNER = r"""[bold bright_green]
   ██████╗██╗  ██╗██████╗  ██████╗ ███╗   ██╗ ██████╗ ███████╗██╗ ██████╗ ██╗  ██╗████████╗
  ██╔════╝██║  ██║██╔══██╗██╔═══██╗████╗  ██║██╔═══██╗██╔════╝██║██╔════╝ ██║  ██║╚══██╔══╝
  ██║     ███████║██████╔╝██║   ██║██╔██╗ ██║██║   ██║███████╗██║██║  ███╗███████║   ██║
  ██║     ██╔══██║██╔══██╗██║   ██║██║╚██╗██║██║   ██║╚════██║██║██║   ██║██╔══██║   ██║
  ╚██████╗██║  ██║██║  ██║╚██████╔╝██║ ╚████║╚██████╔╝███████║██║╚██████╔╝██║  ██║   ██║
   ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝ ╚═════╝ ╚══════╝╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝
[/bold bright_green]
[dim white]      ⟡ v1.0 · AI-Powered Deep Forensic Artifact & Case Investigator · DFIR Engine ⟡[/dim white]
[dim cyan]                    Digital Forensics & Incident Response  |  Bahasa Indonesia Report[/dim cyan]
"""

# ============================================================
#  UI HELPER FUNCTIONS
# ============================================================

def print_banner() -> None:
    """Tampilkan banner ASCII ChronoSight v1.0."""
    console.print(_BANNER)


def _status(msg: str) -> None:
    console.print(f"  [info]⟐[/info]  {msg}")


def _info(msg: str) -> None:
    console.print(f"  [info]ℹ[/info]  {msg}")


def _success(msg: str) -> None:
    console.print(f"  [success]✔[/success]  {msg}")


def _warning(msg: str) -> None:
    console.print(f"  [warning]⚠[/warning]  {msg}")


def _error(msg: str) -> None:
    console.print(f"  [error]✘[/error]  {msg}")


def _human_size(nbytes: int) -> str:
    """Konversi byte ke string berukuran manusiawi (misal: 4.2 MiB)."""
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if abs(nbytes) < 1024:
            return f"{nbytes:.1f} {unit}"
        nbytes /= 1024  # type: ignore[assignment]
    return f"{nbytes:.1f} PiB"


# ============================================================
#  KONSTANTA & PETA EKSTENSI
# ============================================================

_HASH_BUF  = 65_536       # 64 KiB — buffer baca hash
_MAX_HASH  = 2 << 30      # 2 GiB  — lewati file lebih besar dari ini

IMAGE_EXTS       = frozenset({".jpg", ".jpeg", ".png", ".bmp", ".tiff", ".tif", ".gif", ".webp"})
PDF_EXTS         = frozenset({".pdf"})
SPREADSHEET_EXTS = frozenset({".xlsx", ".xls"})
DOCX_EXTS        = frozenset({".docx"})
TEXT_EXTS        = frozenset({
    ".txt", ".log", ".csv", ".md", ".ini", ".conf",
    ".json", ".xml", ".yaml", ".yml", ".sh", ".py",
    ".bat", ".ps1", ".sql", ".html", ".htm", ".cfg",
})


# ============================================================
#  1. METADATA DASAR — HASH & MAC TIMES
# ============================================================

def _compute_hashes(filepath: Path) -> dict[str, str]:
    """
    Hitung hash MD5 dan SHA-256 untuk chain-of-custody forensik.

    File dibaca secara inkremental (64 KiB per blok) sehingga file
    berukuran besar tidak menyebabkan kehabisan memori.
    File > 2 GiB dilewati untuk menghindari stall.

    Args:
        filepath: Path ke file target.

    Returns:
        Dict dengan kunci ``"md5"`` dan ``"sha256"`` berisi hex-digest.
    """
    try:
        if filepath.stat().st_size > _MAX_HASH:
            return {"md5": "SKIPPED_TOO_LARGE", "sha256": "SKIPPED_TOO_LARGE"}
        md5    = hashlib.md5()
        sha256 = hashlib.sha256()
        with open(filepath, "rb") as fh:
            while chunk := fh.read(_HASH_BUF):
                md5.update(chunk)
                sha256.update(chunk)
        return {"md5": md5.hexdigest(), "sha256": sha256.hexdigest()}
    except PermissionError:
        return {"md5": "PERMISSION_DENIED", "sha256": "PERMISSION_DENIED"}
    except OSError as exc:
        return {"md5": f"ERROR:{exc}", "sha256": f"ERROR:{exc}"}


def _epoch_iso(epoch: float) -> str:
    """Konversi Unix epoch ke string ISO-8601 UTC."""
    return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()


def _mac_times(filepath: Path) -> dict[str, str]:
    """
    Ekstrak MAC times (Modified, Accessed, Created) dari file.

    Di Linux, ``st_ctime`` adalah waktu perubahan inode, bukan waktu
    pembuatan sejati. ``st_birthtime`` hanya tersedia di filesystem
    tertentu (ext4 kernel ≥ 4.11, Btrfs, XFS).

    Args:
        filepath: Path ke file target.

    Returns:
        Dict dengan kunci ``"modified"``, ``"accessed"``, ``"created"`` (ISO-8601 UTC).
    """
    st    = filepath.stat()
    birth = getattr(st, "st_birthtime", None)
    return {
        "modified": _epoch_iso(st.st_mtime),
        "accessed": _epoch_iso(st.st_atime),
        "created":  _epoch_iso(birth) if birth else _epoch_iso(st.st_ctime),
    }


def _filetype(filepath: Path) -> str:
    """Kembalikan label tipe file berdasarkan bit mode stat."""
    try:
        m = filepath.lstat().st_mode
    except OSError:
        return "unknown"
    if stat.S_ISREG(m): return "regular"
    if stat.S_ISLNK(m): return "symlink"
    if stat.S_ISDIR(m): return "directory"
    if stat.S_ISFIFO(m): return "fifo"
    if stat.S_ISSOCK(m): return "socket"
    return "special"


# ============================================================
#  2. EKSTRAKTOR MENDALAM — GAMBAR (EXIF / GPS)
# ============================================================

def _extract_image(filepath: Path) -> dict[str, Any]:
    """
    Ekstrak metadata EXIF dari file gambar JPEG/PNG menggunakan Pillow.

    Signifikansi Forensik:
        - DateTimeOriginal : Waktu pengambilan asli — bisa berbeda dari
                             MAC times filesystem (indikator manipulasi).
        - GPS Coordinates  : Bukti lokasi fisik.
        - Camera Make/Model: Identifikasi perangkat dan atribusi.
        - Software Tag     : Deteksi perangkat lunak editing (Photoshop,
                             GIMP) yang mengindikasikan kemungkinan pemalsuan.

    Args:
        filepath: Path ke file gambar.

    Returns:
        Dict berisi data EXIF dan GPS yang terdekode.
    """
    try:
        from PIL import Image
        from PIL.ExifTags import TAGS, GPSTAGS
    except ImportError:
        return {"error": "Pillow tidak terinstal — jalankan: pip install Pillow"}

    result: dict[str, Any] = {
        "format": None, "mode": None, "size_pixels": None,
        "camera_make": None, "camera_model": None, "software": None,
        "datetime_original": None, "datetime_digitized": None,
        "gps_latitude": None, "gps_longitude": None, "gps_altitude": None,
        "gps_raw": {}, "exif_summary": {},
    }

    try:
        with Image.open(filepath) as img:
            result["format"]      = img.format
            result["mode"]        = img.mode
            result["size_pixels"] = f"{img.width}x{img.height}"

            exif_raw = img._getexif()  # type: ignore[attr-defined]
            if not exif_raw:
                result["note"] = "Tidak ada data EXIF ditemukan."
                return result

            gps_ifd: dict[int, Any] = {}

            for tag_id, value in exif_raw.items():
                tag = TAGS.get(tag_id, str(tag_id))

                # Lewati blob biner besar (thumbnail, MakerNote)
                if isinstance(value, bytes) and len(value) > 128:
                    display = f"<binary: {len(value)} bytes>"
                else:
                    display = str(value)

                result["exif_summary"][str(tag)] = display

                match str(tag):
                    case "Make":              result["camera_make"]       = display
                    case "Model":             result["camera_model"]      = display
                    case "Software":          result["software"]          = display
                    case "DateTimeOriginal":  result["datetime_original"] = display
                    case "DateTimeDigitized": result["datetime_digitized"]= display
                    case "GPSInfo":
                        if isinstance(value, dict):
                            gps_ifd = value
                            for gid, gval in value.items():
                                gtag = GPSTAGS.get(gid, str(gid))
                                result["gps_raw"][str(gtag)] = str(gval)

            # Konversi GPS ke koordinat desimal
            if gps_ifd:
                def _to_dec(coord: Any, ref: str) -> float | None:
                    try:
                        d, m, s = coord
                        dec = float(d) + float(m)/60 + float(s)/3600
                        return round(-dec if ref in ("S", "W") else dec, 7)
                    except Exception:
                        return None

                lat     = gps_ifd.get(2); lat_ref = str(gps_ifd.get(1, "N"))
                lon     = gps_ifd.get(4); lon_ref = str(gps_ifd.get(3, "E"))
                alt_val = gps_ifd.get(6)

                if lat and lon:
                    result["gps_latitude"]  = _to_dec(lat, lat_ref)
                    result["gps_longitude"] = _to_dec(lon, lon_ref)
                if alt_val:
                    try:    result["gps_altitude"] = f"{float(alt_val):.1f}m"
                    except: result["gps_altitude"] = str(alt_val)

    except Exception as exc:
        result["error"] = str(exc)

    return result


# ============================================================
#  3. EKSTRAKTOR MENDALAM — PDF
# ============================================================

def _extract_pdf(filepath: Path) -> dict[str, Any]:
    """
    Ekstrak metadata dokumen dan pratinjau teks halaman pertama dari PDF.

    Signifikansi Forensik:
        - Author/Creator    : Atribusi asal dokumen — ketidaksesuaian
                              dengan klaim dapat mengindikasikan pemalsuan.
        - CreationDate      : Waktu pembuatan asli — bandingkan dengan
                              MAC times untuk mendeteksi manipulasi.
        - Producer          : Aplikasi pembuat PDF (misal: "Microsoft Word").
        - is_encrypted      : PDF terenkripsi mungkin menyembunyikan data.
        - text_preview      : Deteksi kata kunci, pesan terselubung, atau
                              konten sensitif tanpa membuka file di viewer.

    Args:
        filepath: Path ke file PDF.

    Returns:
        Dict berisi metadata PDF dan pratinjau teks.
    """
    try:
        from pypdf import PdfReader
    except ImportError:
        return {"error": "pypdf tidak terinstal — jalankan: pip install pypdf"}

    result: dict[str, Any] = {
        "page_count": None, "title": None, "author": None,
        "subject": None, "creator": None, "producer": None,
        "creation_date": None, "modification_date": None,
        "keywords": None, "is_encrypted": False,
        "text_preview": None,
    }

    try:
        reader = PdfReader(str(filepath))
        result["is_encrypted"] = reader.is_encrypted
        result["page_count"]   = len(reader.pages)

        meta = reader.metadata
        if meta:
            result["title"]    = meta.title
            result["author"]   = meta.author
            result["subject"]  = meta.subject
            result["creator"]  = meta.creator
            result["producer"] = meta.producer
            result["keywords"] = getattr(meta, "keywords", None) or meta.get("/Keywords")

            creation = getattr(meta, "creation_date", None) or meta.get("/CreationDate")
            moddate  = getattr(meta, "modification_date", None) or meta.get("/ModDate")
            result["creation_date"]    = str(creation).strip() if creation else None
            result["modification_date"]= str(moddate).strip()  if moddate  else None

        # Pratinjau teks halaman pertama (maks. 500 karakter)
        if not reader.is_encrypted and reader.pages:
            try:
                raw  = reader.pages[0].extract_text() or ""
                clean = " ".join(raw.split())
                result["text_preview"] = clean[:500]
            except Exception as exc:
                result["text_preview"] = f"<gagal ekstrak teks: {exc}>"
        elif reader.is_encrypted:
            result["text_preview"] = "<PDF terenkripsi — teks tidak dapat diekstrak>"

    except Exception as exc:
        result["error"] = str(exc)

    return result


# ============================================================
#  4. EKSTRAKTOR MENDALAM — SPREADSHEET EXCEL (HIDDEN SHEET)
# ============================================================

def _extract_spreadsheet(filepath: Path) -> dict[str, Any]:
    """
    Ekstrak metadata dan deteksi lembar tersembunyi dari file Excel.

    Signifikansi Forensik:
        - hidden_sheets      : Lembar yang disembunyikan melalui Format >
                               Sheet > Hide. Dapat berisi data staging atau
                               muatan eksfiltrasi tersembunyi.
        - very_hidden_sheets : Lembar dengan state="veryHidden" — TIDAK dapat
                               diperlihatkan melalui UI normal, hanya melalui
                               kode VBA atau alat forensik. Indikator kuat
                               anti-forensik / penyembunyian data disengaja.
        - Creator/LastModifiedBy: Atribusi untuk chain-of-custody.

    Args:
        filepath: Path ke file .xlsx atau .xls.

    Returns:
        Dict berisi info lembar, flag hidden_content, dan properti dokumen.
    """
    result: dict[str, Any] = {
        "sheet_count": None, "sheet_names": [],
        "visible_sheets": [], "hidden_sheets": [],
        "very_hidden_sheets": [], "has_hidden_content": False,
        "active_sheet": None, "properties": {},
    }

    # Format .xls (Excel 97-2003) tidak didukung openpyxl
    if filepath.suffix.lower() == ".xls":
        result["note"] = "Format .xls terdeteksi — openpyxl hanya mendukung .xlsx. Konversi ke .xlsx untuk analisis mendalam."
        result["format"] = "legacy_xls"
        return result

    try:
        import openpyxl
    except ImportError:
        return {"error": "openpyxl tidak terinstal — jalankan: pip install openpyxl"}

    try:
        wb = openpyxl.load_workbook(str(filepath), read_only=True, data_only=True)
        result["sheet_count"] = len(wb.sheetnames)
        result["sheet_names"] = list(wb.sheetnames)

        try:
            result["active_sheet"] = wb.active.title if wb.active else None
        except Exception:
            pass

        # ── PEMERIKSAAN FORENSIK UTAMA: Deteksi Visibilitas Lembar ──
        # sheet_state: "visible" | "hidden" | "veryHidden"
        for ws in wb.worksheets:
            state = getattr(ws, "sheet_state", "visible") or "visible"
            if state == "hidden":
                result["hidden_sheets"].append(ws.title)
                result["has_hidden_content"] = True
            elif state == "veryHidden":
                # TEMUAN KRITIS — tidak terlihat di UI normal sama sekali
                result["very_hidden_sheets"].append(ws.title)
                result["has_hidden_content"] = True
            else:
                result["visible_sheets"].append(ws.title)

        # Properti dokumen (penulis, tanggal)
        props = wb.properties
        if props:
            result["properties"] = {
                "creator":          props.creator,
                "last_modified_by": props.lastModifiedBy,
                "created":          str(props.created)  if props.created  else None,
                "modified":         str(props.modified) if props.modified else None,
                "title":            props.title,
                "subject":          props.subject,
                "keywords":         props.keywords,
                "category":         props.category,
            }

        wb.close()

    except Exception as exc:
        result["error"] = str(exc)

    return result


# ============================================================
#  5. EKSTRAKTOR MENDALAM — TEKS / LOG / CSV
# ============================================================

_ENCODINGS = ("utf-8", "utf-16", "latin-1", "cp1252")


def _extract_text(filepath: Path, max_chars: int = 500) -> dict[str, Any]:
    """
    Ekstrak pratinjau konten dan statistik dari file teks.

    Mencoba berbagai encoding secara berurutan. Berguna untuk mendeteksi
    pesan terselubung, kata sandi dalam plaintext, kredensial C2, atau
    konten log yang mencurigakan tanpa membuka file secara lengkap.

    Args:
        filepath:  Path ke file teks.
        max_chars: Jumlah karakter maksimum untuk pratinjau.

    Returns:
        Dict berisi encoding, jumlah baris/kata/karakter, dan pratinjau.
    """
    result: dict[str, Any] = {
        "encoding_detected": None,
        "line_count": None, "word_count": None,
        "char_count": None, "preview": None,
    }

    for enc in _ENCODINGS:
        try:
            text = filepath.read_text(encoding=enc, errors="strict")
            result["encoding_detected"] = enc
            result["line_count"]        = text.count("\n") + (1 if text else 0)
            result["word_count"]        = len(text.split())
            result["char_count"]        = len(text)
            result["preview"]           = text[:max_chars].strip()
            return result
        except (UnicodeDecodeError, UnicodeError):
            continue
        except PermissionError:
            result["error"] = "Akses ditolak (PermissionError)."
            return result
        except OSError as exc:
            result["error"] = str(exc)
            return result

    result["error"] = "Tidak dapat mendekode file — kemungkinan file biner dengan ekstensi teks (indikator anti-forensik)."
    return result


# ============================================================
#  6. ORKESTRATOR — PEMINDAI DIREKTORI
# ============================================================

def scan_directory(target: Path) -> list[dict[str, Any]]:
    """
    Pindai *target* secara rekursif dan ekstrak metadata forensik mendalam
    untuk setiap file yang ditemukan.

    Untuk setiap file, fungsi ini merekam:
        - Nama file, path lengkap, direktori, ekstensi, tipe file
        - Ukuran dalam byte
        - MAC timestamps (Modified / Accessed / Created) dalam ISO-8601 UTC
        - Hash MD5 dan SHA-256 untuk chain-of-custody
        - Metadata mendalam sesuai kategori (EXIF, PDF, hidden sheet, teks)

    Symbolic link TIDAK diikuti (followlinks=False) untuk mencegah loop
    tak terbatas dan menjaga bukti serangan berbasis symlink.

    Args:
        target: Direktori root untuk dipindai.

    Returns:
        List dict artefak, satu per file.

    Raises:
        SystemExit: Jika *target* tidak ada atau bukan direktori.
    """
    if not target.exists():
        _error(f"Path target tidak ditemukan: {target}")
        raise SystemExit(1)
    if not target.is_dir():
        _error(f"Path target bukan direktori: {target}")
        raise SystemExit(1)

    # Pass pertama: hitung total file untuk progress bar
    file_list: list[Path] = []
    for root, _dirs, files in os.walk(target, followlinks=False):
        for fname in files:
            file_list.append(Path(root) / fname)

    artifacts: list[dict[str, Any]] = []
    skipped = 0

    with Progress(
        SpinnerColumn(),
        TextColumn("[bold cyan]Mengekstrak Artefak Mendalam"),
        BarColumn(bar_width=40),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        console=console,
        transient=False,
    ) as progress:
        task = progress.add_task("scan", total=len(file_list))

        for filepath in file_list:
            progress.advance(task)

            # Lewati symlink rusak — metadata tidak dapat diakses
            if filepath.is_symlink() and not filepath.exists():
                skipped += 1
                continue

            try:
                st = filepath.stat()
            except PermissionError:
                _warning(f"Akses ditolak: {filepath}")
                skipped += 1
                continue
            except OSError as exc:
                _warning(f"Error OS: {filepath} — {exc}")
                skipped += 1
                continue

            ext = filepath.suffix.lower()

            # ── Rekaman Artefak Dasar ──
            artifact: dict[str, Any] = {
                "filename":  filepath.name,
                "path":      str(filepath.resolve()),
                "directory": str(filepath.parent.resolve()),
                "extension": ext,
                "size_bytes": st.st_size,
                "file_type": _filetype(filepath),
                "timestamps": _mac_times(filepath),
                "hashes":    _compute_hashes(filepath),
                "deep_metadata": {},
            }

            # ── Dispatch ke Ekstraktor Mendalam ──
            try:
                if ext in IMAGE_EXTS:
                    artifact["deep_metadata"] = {"category": "image",       "data": _extract_image(filepath)}
                elif ext in PDF_EXTS:
                    artifact["deep_metadata"] = {"category": "pdf",         "data": _extract_pdf(filepath)}
                elif ext in SPREADSHEET_EXTS:
                    artifact["deep_metadata"] = {"category": "spreadsheet", "data": _extract_spreadsheet(filepath)}
                elif ext in TEXT_EXTS:
                    artifact["deep_metadata"] = {"category": "text",        "data": _extract_text(filepath)}
                # File tanpa ekstraktor cocok dibiarkan dengan deep_metadata kosong
            except Exception as exc:
                artifact["deep_metadata"] = {"category": "error", "data": {"error": str(exc)}}

            artifacts.append(artifact)

    if skipped:
        _warning(f"Dilewati: {skipped} file (PermissionError atau symlink rusak).")

    return artifacts


# ============================================================
#  7. DETEKSI FLAG FORENSIK (UNTUK TAMPILAN TABEL)
# ============================================================

def _forensic_flags(artifact: dict[str, Any]) -> str:
    """Kembalikan string indikator flag forensik untuk satu artefak."""
    flags: list[str] = []
    dm   = artifact.get("deep_metadata") or {}
    data = dm.get("data") or {}
    cat  = dm.get("category", "")

    if cat == "spreadsheet":
        if data.get("very_hidden_sheets"):
            flags.append("[flag]🚨 VERY HIDDEN[/flag]")
        elif data.get("hidden_sheets"):
            flags.append("[flag]⚠ HIDDEN SHEET[/flag]")

    if cat == "image":
        if data.get("gps_latitude") is not None:
            flags.append("📍 GPS")
        if data.get("datetime_original"):
            flags.append("📷 EXIF-TS")
        sw = (data.get("software") or "").lower()
        if any(k in sw for k in ("photoshop", "gimp", "lightroom", "affinity")):
            flags.append("[warning]✏ EDITED[/warning]")

    if cat == "pdf":
        if data.get("is_encrypted"):
            flags.append("🔒 ENCRYPTED")

    if cat == "text":
        err = data.get("error", "")
        if "biner" in err.lower() or "anti-forensik" in err.lower():
            flags.append("[flag]⚠ BINARY-AS-TEXT[/flag]")

    return " ".join(flags) if flags else "—"


# ============================================================
#  8. TAMPILAN TABEL TERMINAL
# ============================================================

def _print_artifact_table(artifacts: list[dict[str, Any]], limit: int = 25) -> None:
    """Tampilkan tabel artefak dengan indikator flag forensik."""
    tbl = Table(
        title="[header]🔍 Artefak yang Diekstrak (Pratinjau)[/header]",
        border_style="bright_green", header_style="bold cyan",
        padding=(0, 1), show_lines=False,
    )
    tbl.add_column("Nama Berkas",          style="white",         max_width=32, no_wrap=True)
    tbl.add_column("Ext",                  style="bright_yellow", width=7,      justify="center")
    tbl.add_column("Ukuran",               style="cyan",          width=9,      justify="right")
    tbl.add_column("Dimodifikasi (UTC)",   style="white",         width=20)
    tbl.add_column("Kategori",             style="bright_magenta",width=13)
    tbl.add_column("Indikator Forensik",   style="white",         min_width=18)

    for a in artifacts[:limit]:
        tbl.add_row(
            a["filename"],
            a.get("extension") or "—",
            _human_size(a["size_bytes"]),
            a["timestamps"]["modified"][:19].replace("T", " "),
            (a.get("deep_metadata") or {}).get("category", "—") or "—",
            _forensic_flags(a),
        )

    if len(artifacts) > limit:
        tbl.add_row(f"[muted]… dan {len(artifacts)-limit} berkas lainnya[/muted]","","","","","")

    console.print(); console.print(tbl); console.print()


def _print_summary_table(artifacts: list[dict[str, Any]]) -> None:
    """Tampilkan tabel ringkasan kategori dan anomali forensik."""
    if not artifacts:
        return

    cats: dict[str, int] = {}
    hidden_cnt = very_hidden_cnt = gps_cnt = encrypted_cnt = edited_cnt = 0

    for a in artifacts:
        dm   = a.get("deep_metadata") or {}
        cat  = dm.get("category", "other") or "other"
        data = dm.get("data") or {}
        cats[cat] = cats.get(cat, 0) + 1

        if cat == "spreadsheet":
            if data.get("hidden_sheets"):      hidden_cnt      += 1
            if data.get("very_hidden_sheets"): very_hidden_cnt += 1
        if cat == "image":
            if data.get("gps_latitude") is not None: gps_cnt  += 1
            sw = (data.get("software") or "").lower()
            if any(k in sw for k in ("photoshop","gimp","lightroom")): edited_cnt += 1
        if cat == "pdf" and data.get("is_encrypted"): encrypted_cnt += 1

    tbl = Table(
        title="[header]📊 Ringkasan Pemindaian & Anomali Forensik[/header]",
        border_style="bright_green", header_style="bold cyan", padding=(0, 1),
    )
    tbl.add_column("Metrik",  style="bold white", min_width=40)
    tbl.add_column("Nilai",   style="bright_green", justify="right")

    tbl.add_row("Total Berkas Diproses", str(len(artifacts)))
    for cat, cnt in sorted(cats.items()):
        tbl.add_row(f"  └─ {cat.capitalize()}", str(cnt))
    tbl.add_row("─"*40, "─"*6)
    tbl.add_row("⚠️   Spreadsheet dengan Hidden Sheet",         str(hidden_cnt))
    tbl.add_row("🚨  Spreadsheet dengan VeryHidden Sheet",       str(very_hidden_cnt))
    tbl.add_row("📍  Gambar dengan Koordinat GPS",               str(gps_cnt))
    tbl.add_row("✏️   Gambar yang Terindikasi Diedit",           str(edited_cnt))
    tbl.add_row("🔒  PDF Terenkripsi",                           str(encrypted_cnt))

    console.print(); console.print(tbl); console.print()


# ============================================================
#  9. SISTEM PROMPT AI DFIR (BAHASA INDONESIA)
# ============================================================

_DFIR_SYSTEM_PROMPT = """\
Kamu adalah **ChronoSight AI** — Analis Forensik Digital Senior (DFIR) \
dengan pengalaman lebih dari 20 tahun di bidang investigasi insiden siber, \
analisis malware, pemulihan bukti digital, dan penyidikan kejahatan siber.

Kamu akan menerima data JSON berisi metadata artefak digital yang telah \
diekstraksi dari direktori target. Data mencakup MAC timestamps \
(Modified/Accessed/Created), hash kriptografis MD5/SHA256, serta metadata \
mendalam per kategori: EXIF gambar (kamera, GPS, tanggal asli), metadata \
PDF (penulis, tanggal, teks), lembar Excel tersembunyi (hidden/veryHidden), \
dan pratinjau konten teks/log.

Berikan laporan analisis kasus DFIR yang komprehensif dalam **Bahasa Indonesia** \
dengan tiga (3) bagian terstruktur berikut:

---

## 📁 Bagian 1: Tabel Bukti Digital Utama

Buat tabel Markdown berisi **hingga 10 berkas bukti digital paling relevan**:

| No | Nama Berkas | Lokasi Direktori | Kategori | Analisis & Alasan |
|---|---|---|---|---|

- `🔴 Relevan` — Berkas yang secara langsung mendukung hipotesis kasus
- `⚪ Tidak Relevan` — Berkas yang tidak menunjukkan aktivitas mencurigakan

Kolom Analisis & Alasan: jelaskan singkat mengapa relevan atau tidak (maks. 2 kalimat).

---

## 🔍 Bagian 2: Jawaban Investigasi

Jawab keempat pertanyaan berikut secara rinci berdasarkan HANYA data JSON yang diberikan:

**1. Bukti Akses & Penyalinan**
Apakah ada bukti konkret bahwa berkas diakses atau disalin secara tidak sah? \
Rujuk pada timestamp MAC spesifik dan pola yang mencurigakan.

**2. Metode & Tujuan Eksfiltrasi**
Bagaimana dan ke mana data mungkin dieksfiltrasi? Identifikasi berkas yang \
paling mungkin menjadi muatan eksfiltrasi berdasarkan ukuran, jenis, dan metadata.

**3. Komunikasi Terselubung**
Apakah ada indikasi pesan tersembunyi, steganografi, atau komunikasi terselubung?

**4. Anti-Forensik & Data Tersembunyi**
Apakah ada bukti upaya anti-forensik: manipulasi timestamp, lembar Excel \
veryHidden, berkas biner berekstensi teks, atau teknik penyembunyian lainnya?

Jika ada **skenario/pertanyaan spesifik dari penyelidik**, jawab di sub-bagian \
bertajuk **"Jawaban Skenario Penyelidik"**.

---

## ⚖️ Bagian 3: Kesimpulan Forensik & Validasi Chain of Custody

**3.1 Kesimpulan Investigasi** — Rangkuman komprehensif temuan utama.

**3.2 Penilaian Risiko** — 🔴 Kritis / 🟠 Tinggi / 🟡 Sedang / 🟢 Rendah + justifikasi.

**3.3 Validasi Chain of Custody (Hash)**

| Nama Berkas | MD5 | SHA256 |
|---|---|---|

(Cantumkan hingga 5 berkas kunci untuk dokumentasi rantai bukti.)

**3.4 Rekomendasi Tindak Lanjut** — Langkah konkret bagi tim investigasi.

---

⚠️ INTEGRITAS: Jangan mengarang data yang tidak ada dalam input JSON. \
Jika bukti tidak cukup, nyatakan: *"Bukti tidak mencukupi untuk menjawab pertanyaan ini."*
"""


# ============================================================
#  10. ENGINE ANALISIS AI — GEMINI
# ============================================================

def _analyze_with_ai(
    artifacts: list[dict[str, Any]],
    api_key: str,
    scenario: str | None = None,
    model: str = "gemini-3.6-flash",
) -> str | None:
    """
    Kirim artefak forensik ke Gemini AI untuk analisis kasus DFIR.

    Menggunakan SDK google-genai >= 2.3.0 (SDK modern).
    SDK google-generativeai (lama) sudah deprecated — jangan digunakan.
    Model gemini-1.5-flash juga sudah deprecated — diganti gemini-3.6-flash.

    Fitur Auto-fallback: Jika model utama tidak tersedia (404), sistem
    otomatis mencoba model cadangan dalam urutan berikut:
        gemini-3.6-flash → gemini-3.8-flash → gemini-flash-latest

    Args:
        artifacts: List dict artefak dari scan_directory().
        api_key:   Google Gemini API key.
        scenario:  Skenario/pertanyaan investigasi opsional (teks).
        model:     Model Gemini yang digunakan.

    Returns:
        Laporan Markdown sebagai string, atau None jika gagal.
    """
    try:
        from google import genai
        from google.genai import types
    except ImportError:
        _error(
            "Paket [bold]google-genai[/bold] belum terinstal.\n"
            "  Instal dengan: [cyan]pip install google-genai[/cyan]"
        )
        return None

    try:
        client = genai.Client(api_key=api_key)
    except Exception as exc:
        _error(f"Gagal menginisialisasi Gemini client: {exc}")
        return None

    # Pembatasan payload (batas token)
    max_arts = 300
    if len(artifacts) > max_arts:
        _info(f"Artefak terlalu banyak ({len(artifacts)}), mengirim {max_arts} terakhir.")
        payload = artifacts[-max_arts:]
    else:
        payload = artifacts

    arts_json   = json.dumps(payload, indent=2, ensure_ascii=False)
    user_prompt = (
        "Analisis artefak forensik digital berikut dan hasilkan laporan DFIR "
        "lengkap sesuai instruksi sistem.\n\n"
        f"**DATA ARTEFAK FORENSIK (JSON):**\n```json\n{arts_json}\n```\n"
    )
    if scenario:
        user_prompt += (
            f"\n**SKENARIO & PERTANYAAN INVESTIGASI DARI PENYELIDIK:**\n"
            f"```\n{scenario}\n```\n"
        )

    _status(
        f"Mengirim [bold]{len(payload)}[/bold] artefak ke Gemini AI "
        f"([cyan]{model}[/cyan]) untuk analisis DFIR…"
    )

    afc_cfg = types.AutomaticFunctionCallingConfig(disable=True)
    cfg     = types.GenerateContentConfig(
        system_instruction=_DFIR_SYSTEM_PROMPT,
        temperature=0.10,       # Presisi maksimum untuk analisis forensik
        max_output_tokens=8192,
        automatic_function_calling=afc_cfg,
    )

    # Chain model fallback
    candidates: list[str] = [model]
    for fb in ("gemini-3.6-flash", "gemini-3.8-flash", "gemini-flash-latest"):
        if fb not in candidates:
            candidates.append(fb)

    response   = None
    last_exc: Exception | None = None

    for active_model in candidates:
        try:
            response = client.models.generate_content(
                model=active_model,
                contents=user_prompt,
                config=cfg,
            )
            break
        except Exception as exc:
            last_exc = exc
            emsg     = str(exc)
            if "NOT_FOUND" in emsg or "404" in emsg or "no longer available" in emsg:
                continue   # Coba model berikutnya
            elif "PERMISSION_DENIED" in emsg or "API_KEY_INVALID" in emsg:
                _error("API key tidak valid — periksa di https://aistudio.google.com/apikey")
                return None
            elif "RESOURCE_EXHAUSTED" in emsg or "429" in emsg:
                _error("Rate limit terlampaui. Tunggu sebentar lalu coba lagi.")
                return None
            elif "DEADLINE_EXCEEDED" in emsg or "timeout" in emsg.lower():
                _error("Request timeout. Coba scan direktori yang lebih kecil.")
                return None
            else:
                _error(f"Gemini API error: {exc}")
                return None

    if response is None:
        _error(f"Semua model gagal. Error terakhir: {last_exc}")
        return None

    # Ekstrak teks respons
    try:
        text = response.text
    except (AttributeError, ValueError):
        try:
            text = response.candidates[0].content.parts[0].text
        except Exception:
            _error("Respon Gemini kosong atau tidak dapat diurai.")
            return None

    if not text:
        _error("Gemini mengembalikan respon kosong.")
        return None

    # Render laporan di terminal
    console.print()
    console.print(
        Panel(
            Markdown(text),
            title="[bold red]⚡ ChronoSight AI — Laporan Analisis DFIR ⚡[/bold red]",
            subtitle="[dim white]Digital Forensics & Incident Response  |  output: Bahasa Indonesia[/dim white]",
            border_style="red",
            padding=(1, 2),
        )
    )
    return text


# ============================================================
#  11. CLI ARGUMENT PARSER
# ============================================================

def _build_parser() -> argparse.ArgumentParser:
    """Bangun argument parser CLI untuk ChronoSight v2.0."""
    p = argparse.ArgumentParser(
        prog="chronosight",
        description=(
            "ChronoSight v2.0 — AI-Powered Deep Forensic Artifact & Case Investigator.\n"
            "Ekstrak metadata mendalam (EXIF, PDF, hidden sheet, teks) dari artefak digital\n"
            "dan gunakan Gemini AI untuk menghasilkan laporan DFIR terstruktur dalam Bahasa Indonesia."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Contoh Penggunaan:\n"
            "  chronosight -t /evidence/kasus001\n"
            "  chronosight -t /mnt/flashdisk -k AIza... -s 'Apakah ada file yang diekstrak?'\n"
            "  chronosight -t /artifacts -s skenario.txt -o laporan_dfir.md\n"
            "  GEMINI_API_KEY=AIza... chronosight -t /forensic/data\n"
            "  chronosight -t /tmp/artefak --no-ai   # hanya ekstraksi metadata\n"
        ),
    )
    p.add_argument("-t","--target",   type=str, required=True,
                   help="Direktori target yang berisi artefak forensik.")
    p.add_argument("-k","--api-key",  type=str, default=None,
                   help="Google Gemini API key (default: baca GEMINI_API_KEY env var).")
    p.add_argument("-s","--scenario", type=str, default=None,
                   help="Skenario investigasi — teks langsung atau path ke file .txt.")
    p.add_argument("-o","--output",   type=str, default=None,
                   help="Path file untuk menyimpan laporan DFIR (format Markdown).")
    p.add_argument("-m","--model",    type=str, default="gemini-3.6-flash",
                   help="Model Gemini yang digunakan (default: gemini-3.6-flash).")
    p.add_argument("--no-ai",         action="store_true", default=False,
                   help="Lewati analisis AI — hanya ekstraksi metadata.")
    p.add_argument("-v","--version",  action="version", version=f"%(prog)s {__version__}")
    return p


def _resolve_scenario(raw: str | None) -> str | None:
    """
    Resolusi argumen --scenario: teks langsung atau path ke file .txt.

    Args:
        raw: Nilai mentah dari argumen --scenario.

    Returns:
        String skenario, atau None jika tidak diberikan.
    """
    if not raw:
        return None
    path = Path(raw)
    if path.exists() and path.is_file():
        try:
            text = path.read_text(encoding="utf-8").strip()
            _info(f"Skenario dimuat dari berkas: [bold]{path}[/bold]")
            return text
        except Exception as exc:
            _warning(f"Gagal membaca berkas skenario: {exc}")
    return raw.strip()


# ============================================================
#  12. ENTRY POINT UTAMA
# ============================================================

def main() -> None:
    """
    Pipeline investigasi ChronoSight v2.0:

        Fase 1 · Ekstraksi Artefak Mendalam
        Fase 2 · Pratinjau Artefak di Terminal
        Fase 3 · Analisis DFIR oleh Gemini AI
        Fase 4 · Ekspor Laporan ke File (opsional)
    """
    parser = _build_parser()
    args   = parser.parse_args()

    # ── Banner ──
    print_banner()

    # ── Resolusi Target ──
    target = Path(args.target).resolve()
    _status(f"Target direktori: [bold]{target}[/bold]")

    # ── Resolusi Skenario ──
    scenario = _resolve_scenario(args.scenario)
    if scenario:
        preview = scenario[:80] + ("…" if len(scenario) > 80 else "")
        _status(f"Skenario investigasi: [italic]{preview}[/italic]")

    # ─────────────────────────────────────────
    # FASE 1: Ekstraksi Artefak Mendalam
    # ─────────────────────────────────────────
    console.rule("[header]Fase 1 · Ekstraksi Artefak Mendalam[/header]", style="bright_green")
    t0        = time.time()
    artifacts = scan_directory(target)
    elapsed   = time.time() - t0

    if not artifacts:
        _warning("Tidak ada berkas yang ditemukan di direktori target.")
        raise SystemExit(0)

    _success(
        f"Berhasil mengekstrak metadata dari [bold]{len(artifacts)}[/bold] berkas "
        f"dalam [bold]{elapsed:.2f}s[/bold]"
    )

    # ─────────────────────────────────────────
    # FASE 2: Pratinjau Artefak di Terminal
    # ─────────────────────────────────────────
    console.rule("[header]Fase 2 · Pratinjau Artefak Terdeteksi[/header]", style="bright_green")
    _print_artifact_table(artifacts)
    _print_summary_table(artifacts)

    # ─────────────────────────────────────────
    # FASE 3: Analisis DFIR oleh Gemini AI
    # ─────────────────────────────────────────
    analysis: str | None = None

    if args.no_ai:
        _info("Analisis AI dilewati (flag --no-ai aktif).")
    else:
        console.rule("[header]Fase 3 · Analisis DFIR oleh Gemini AI[/header]", style="bright_green")
        api_key = args.api_key or os.environ.get("GEMINI_API_KEY")

        if not api_key:
            _warning(
                "Tidak ada Gemini API key.\n"
                "  Gunakan [cyan]-k / --api-key[/cyan] atau set env var "
                "[cyan]GEMINI_API_KEY[/cyan].\n"
                "  Analisis AI dilewati."
            )
        else:
            analysis = _analyze_with_ai(
                artifacts,
                api_key=api_key,
                scenario=scenario,
                model=args.model,
            )

    # ─────────────────────────────────────────
    # FASE 4: Ekspor Laporan ke File
    # ─────────────────────────────────────────
    if analysis and args.output:
        out = Path(args.output).resolve()
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(analysis, encoding="utf-8")
        _success(f"Laporan DFIR disimpan ke [bold]{out}[/bold]")

    # ── Selesai ──
    console.print()
    console.rule("[header]✔ ChronoSight v2.0 Selesai[/header]", style="bright_green")
    console.print()


if __name__ == "__main__":
    main()
