<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10%2B-blue?style=for-the-badge&logo=python&logoColor=white" />
  <img src="https://img.shields.io/badge/Platform-Linux-green?style=for-the-badge&logo=linux&logoColor=white" />
  <img src="https://img.shields.io/badge/AI-Google%20Gemini-orange?style=for-the-badge&logo=google&logoColor=white" />
  <img src="https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge" />
  <img src="https://img.shields.io/badge/DFIR-Forensics-red?style=for-the-badge&logo=hackaday&logoColor=white" />
</p>

<h1 align="center">⟐ ChronoSight</h1>
<h3 align="center">AI-Powered Digital Artifact Timeline Extractor</h3>

<p align="center">
  <i>Scan. Extract. Correlate. Detect.</i>
</p>

<p align="center">
  <a href="#english-documentation">🇬🇧 English</a> &nbsp;|&nbsp;
  <a href="#dokumentasi-bahasa-indonesia">🇮🇩 Bahasa Indonesia</a>
</p>

---

<!-- ============================================================ -->
<!--                   ENGLISH DOCUMENTATION                      -->
<!-- ============================================================ -->

<h2 id="english-documentation">🇬🇧 English Documentation</h2>

**ChronoSight** is an open-source, CLI-based digital forensics tool that reconstructs file-system timelines from a target directory and leverages **Google Gemini AI** to automatically detect malicious anomalies — timestamp manipulation, data exfiltration patterns, malware staging, and more.

Built for incident responders, threat hunters, and security researchers who need fast, AI-augmented triage on Linux systems.

## ✨ Features

| Feature | Description |
|---|---|
| 🔍 **Forensic Extraction** | Recursively extracts MAC timestamps (Modified, Accessed, Created/Changed) and file sizes |
| 🔐 **Integrity Hashing** | Generates MD5 and SHA-256 hashes for every file to maintain chain of custody |
| 📊 **Timeline Builder** | Sorts all artifact events chronologically into a structured JSON report |
| 🤖 **AI Analysis** | Sends the timeline to Google Gemini with a forensic investigator persona to identify IOCs and anomalies |
| 🎨 **Rich Terminal UI** | Beautiful, hacker-themed output with tables, progress bars, and colour-coded severity indicators |
| 💽 **Disk Image Support** | Compatible with mounted `.dd` raw disk images (single & multi-partition) |
| 📦 **Pip-Installable** | Install globally with `pip install .` and use `chronosight` from anywhere |

## 🚀 Quick Start

### Prerequisites

- **Python 3.10+**
- **Linux** (tested on Arch Linux, Debian, Kali Linux, Ubuntu)
- **Google Gemini API Key** — get one free at [Google AI Studio](https://aistudio.google.com/apikey)

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/chronosight.git
cd chronosight

# (Recommended) Create and activate a virtual environment
python3 -m venv venv
source venv/bin/activate

# Install globally (or in a virtual environment)
pip install .

# Verify installation
chronosight --version
```

For development / editable mode:

```bash
pip install -e .
```

### Set Your API Key

```bash
# Option 1: Environment variable (recommended)
export GEMINI_API_KEY="your-api-key-here"

# Option 2: Pass directly via CLI flag
chronosight -t /path/to/scan -k "your-api-key-here"
```

## 📖 Usage

### Basic Scan with AI Analysis

```bash
chronosight -t /var/log
```

### Scan Without AI (Extraction Only)

```bash
chronosight -t /home/user/Downloads --no-ai
```

### Custom Output Path

```bash
chronosight -t /tmp -o /evidence/case001/timeline.json
```

### Save AI Report to File

```bash
chronosight -t /var/log --save-analysis /evidence/case001/analysis.md
```

### Specify a Different Gemini Model

```bash
chronosight -t /etc -m gemini-2.5-pro
```

### Full Example

```bash
export GEMINI_API_KEY="AIza..."
chronosight \
    --target /home/suspect/Documents \
    --output case_timeline.json \
    --save-analysis case_analysis.md \
    --model gemini-3.6-flash
```

---

## 💽 Working with Disk Image Files (`.dd`)

ChronoSight operates at the **filesystem / directory level**. To scan a raw `.dd` disk image, you must first **mount** it to a local directory, then point ChronoSight at that mount point.

> **⚠️ Always mount disk images as read-only (`ro`) to preserve forensic integrity and avoid accidental evidence tampering.**

---

### Step 1 — Determine Partition Type (Single vs. Multi)

Before mounting, you must identify whether your `.dd` file is:
- A **Single-Partition Image** — a direct dump of one filesystem (e.g. only `/dev/sda1`)
- A **Full Disk Image** — a dump of an entire disk that contains a partition table (MBR/GPT) with multiple partitions (e.g. `/dev/sda`)

Use **any one** of the following tools:

#### Method A: `file` Command (Fastest)

```bash
file /path/to/evidence.dd
```

| Output Contains | Meaning | Action |
|---|---|---|
| `ext4 filesystem`, `NTFS`, `FAT32`, `XFS`, etc. | **Single Partition** | Mount directly with `loop` |
| `DOS/MBR boot sector`, `GUID Partition Table (GPT)` | **Full Disk / Multi-Partition** | Use `kpartx` or `losetup` |

**Example outputs:**

```text
# Single Partition (filesystem detected directly)
evidence.dd: Linux rev 1.0 ext4 filesystem data, UUID=3a1b2c3d-...

# Full Disk / Multi-Partition (partition table detected)
evidence.dd: DOS/MBR boot sector; partition 1 : ID=0x83, start-CHS ...
evidence.dd: GUID Partition Table (GPT), ...
```

---

#### Method B: `fdisk -l` (Most Informative)

```bash
fdisk -l /path/to/evidence.dd
```

**Single Partition output** — `fdisk` warns that no valid partition table was found:
```text
Disk evidence.dd doesn't contain a valid partition table.
```
> This is **not** an error — it simply means the image is a raw filesystem partition with no MBR/GPT header.

**Multi-Partition output** — `fdisk` lists individual partitions:
```text
Disk evidence.dd: 64 GiB, 68719476736 bytes, 134217728 sectors
Disklabel type: gpt

Device            Start       End   Sectors  Size Type
evidence.dd1       2048   1050623   1048576  512M EFI System
evidence.dd2    1050624   9439231   8388608    4G Linux swap
evidence.dd3    9439232  41943039  32503808 15.5G Linux filesystem  ← target
```

---

#### Method C: `parted` (Partition Details)

```bash
parted /path/to/evidence.dd print
```

- **Single Partition** → outputs `unrecognised disk label`
- **Multi-Partition** → outputs a full table with `Number`, `Start`, `End`, `File system`, `Flags`

---

#### Method D: `mmls` (Sleuth Kit — Forensic Standard)

```bash
mmls /path/to/evidence.dd
```

The Sleuth Kit's `mmls` is the forensic-grade tool for mapping volume layouts, sector offsets, and partition boundaries. Available on Kali Linux by default; install via `sudo apt install sleuthkit`.

---

### Decision Summary

```
Run: file evidence.dd
        │
        ├── Shows "ext4 / NTFS / FAT32 / XFS ..."
        │         → SINGLE PARTITION
        │         → Go to: Mount (Single Partition)
        │
        └── Shows "DOS/MBR boot sector" or "GPT"
                  → FULL DISK / MULTI-PARTITION
                  → Go to: Mount (Multi-Partition)
```

---

### Step 2A — Mount a Single-Partition Image

```bash
# 1. Create a mount point
sudo mkdir -p /mnt/forensic

# 2. Mount read-only using the loop device
sudo mount -o ro,loop /path/to/evidence.dd /mnt/forensic

# 3. Verify contents
ls /mnt/forensic

# 4. Run ChronoSight
chronosight -t /mnt/forensic -o case_timeline.json --save-analysis case_analysis.md

# 5. Unmount when done
sudo umount /mnt/forensic
```

---

### Step 2B — Mount a Multi-Partition (Full Disk) Image

```bash
# 1. Install kpartx (if not already installed)
sudo apt install kpartx -y         # Debian / Ubuntu / Kali
# sudo pacman -S multipath-tools   # Arch Linux

# 2. Map all partitions read-only (-r flag)
sudo kpartx -av -r /path/to/evidence.dd
# Output example:
#   add map loop0p1 (253:0): 0 1048576 linear /dev/loop0 2048
#   add map loop0p2 (253:1): 0 8388608 linear /dev/loop0 1050624
#   add map loop0p3 (253:2): 0 32503808 linear /dev/loop0 9439232

# 3. List mapped devices to identify target partition
ls /dev/mapper/
# → loop0p1  loop0p2  loop0p3

# 4. Create a mount point
sudo mkdir -p /mnt/forensic

# 5. Mount the target partition (e.g. loop0p3 = Linux filesystem)
sudo mount -o ro /dev/mapper/loop0p3 /mnt/forensic

# 6. Verify contents
ls /mnt/forensic

# 7. Run ChronoSight
chronosight -t /mnt/forensic -o case_timeline.json --save-analysis case_analysis.md

# 8. Unmount and clean up when done
sudo umount /mnt/forensic
sudo kpartx -d /path/to/evidence.dd
```

---

### Alternative: Extract Files Without Mounting (SleuthKit)

If the filesystem is corrupted or cannot be mounted:

```bash
# Install SleuthKit
sudo apt install sleuthkit -y

# Recover all files from the .dd image into a local folder
tsk_recover -e /path/to/evidence.dd /home/user/extracted_files/

# Scan the extracted folder with ChronoSight
chronosight -t /home/user/extracted_files/ -o case_timeline.json
```

---

## 🖥️ CLI Reference

| Flag | Description | Default |
|---|---|---|
| `-t`, `--target` | **(Required)** Directory to scan | — |
| `-k`, `--api-key` | Gemini API key (or use `GEMINI_API_KEY` env var) | `$GEMINI_API_KEY` |
| `-o`, `--output` | Output path for the JSON timeline | `chronosight_timeline.json` |
| `-m`, `--model` | Gemini model to use | `gemini-3.6-flash` |
| `--no-ai` | Skip AI analysis, only extract & build timeline | `false` |
| `--save-analysis` | Save the AI analysis to a Markdown file | — |
| `-v`, `--version` | Show version and exit | — |

## 🏗️ Project Structure

```
chronosight/
├── chronosight/
│   ├── __init__.py       # Package metadata
│   ├── main.py           # CLI entry point & pipeline orchestration
│   ├── extractor.py      # Forensic metadata extraction (MAC times, hashes)
│   ├── timeline.py       # Chronological timeline builder & JSON exporter
│   ├── analyzer.py       # Gemini AI integration & forensic analysis
│   └── ui.py             # Rich terminal theme, tables & display helpers
├── setup.py              # Package installer (pip install .)
├── requirements.txt      # Python dependencies
├── LICENSE               # MIT License
├── .gitignore
└── README.md
```

## 🔬 How It Works

```
┌─────────────┐     ┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│   Target     │────▶│  Forensic    │────▶│   Timeline   │────▶│   Gemini AI  │
│  Directory   │     │  Extractor   │     │   Builder    │     │   Analyzer   │
│  /mnt/forensic│    │ MAC Times    │     │ Chronological│     │ Anomaly      │
│  /var/log    │     │ MD5/SHA-256  │     │ JSON Sort    │     │ Detection    │
│  /home/...   │     │ File Sizes   │     │ Event Stream │     │ IOC Hunting  │
└─────────────┘     └──────────────┘     └──────────────┘     └──────────────┘
```

1. **Extraction** — Recursively walks the target directory, collecting MAC timestamps, file sizes, types, and computing MD5/SHA-256 hashes for forensic integrity.
2. **Timeline Construction** — Expands each file into three events (Modified, Accessed, Created) and sorts them chronologically.
3. **AI Analysis** — The timeline JSON is sent to Gemini with a forensic-investigator system prompt that identifies suspicious patterns, assigns severity ratings, and recommends next steps.

## 🔒 Security & Privacy

- **Local-first** — All file scanning and hashing is performed locally. No file contents are sent to any external service.
- **Metadata only** — Only file paths, timestamps, sizes, and hashes are sent to the Gemini API for analysis. File contents are **never** transmitted.
- **Read-only forensics** — Always mount disk images with `-o ro` to prevent evidence modification.
- **API key safety** — Use environment variables instead of hardcoding API keys.

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## ⚠️ Disclaimer

> **ChronoSight is provided for educational and authorized security research purposes only.**
>
> This tool is designed to assist digital forensics investigators and incident responders in their legitimate work. Users are solely responsible for ensuring they have proper authorization before scanning any system or directory.
>
> The authors assume no liability for misuse of this tool. Always obtain written permission before conducting forensic analysis on systems you do not own.
>
> AI-generated analysis should be treated as **advisory** — always verify findings through manual investigation and established forensic procedures before drawing conclusions or taking action.

## 📄 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

---
---

<!-- ============================================================ -->
<!--               DOKUMENTASI BAHASA INDONESIA                   -->
<!-- ============================================================ -->

<h2 id="dokumentasi-bahasa-indonesia">🇮🇩 Dokumentasi Bahasa Indonesia</h2>

**ChronoSight** adalah alat forensik digital berbasis CLI (Command Line Interface) yang merekonstruksi timeline file-system dari direktori target, kemudian memanfaatkan **Google Gemini AI** untuk mendeteksi anomali berbahaya secara otomatis — seperti manipulasi timestamp, pola eksfiltrasi data, staging malware, dan lainnya.

Dirancang untuk analis incident response, threat hunter, dan peneliti keamanan yang membutuhkan triage cepat berbasis AI di sistem Linux.

## ✨ Fitur Utama

| Fitur | Deskripsi |
|---|---|
| 🔍 **Forensic Extraction** | Mengekstrak MAC timestamp (Modified, Accessed, Created) dan ukuran file secara rekursif |
| 🔐 **Integrity Hashing** | Menghasilkan hash MD5 dan SHA-256 untuk setiap file guna menjaga chain of custody |
| 📊 **Timeline Builder** | Mengurutkan semua event artefak secara kronologis ke dalam laporan JSON terstruktur |
| 🤖 **AI Analysis** | Mengirim timeline ke Google Gemini dengan persona investigator forensik untuk mengidentifikasi IOC dan anomali |
| 🎨 **Rich Terminal UI** | Tampilan terminal bertema hacker yang indah dengan tabel, progress bar, dan indikator severity berwarna |
| 💽 **Dukungan Disk Image** | Kompatibel dengan file disk image `.dd` yang sudah di-mount (partisi tunggal maupun multi-partisi) |
| 📦 **Pip-Installable** | Instal secara global dengan `pip install .` dan gunakan perintah `chronosight` dari mana saja |

## 🚀 Mulai Cepat

### Persyaratan Sistem

- **Python 3.10+**
- **Linux** (diuji pada Arch Linux, Debian, Kali Linux, Ubuntu)
- **Google Gemini API Key** — dapatkan gratis di [Google AI Studio](https://aistudio.google.com/apikey)

### Instalasi

```bash
# Clone repositori
git clone https://github.com/yourusername/chronosight.git
cd chronosight

# (Direkomendasikan) Buat dan aktifkan virtual environment
python3 -m venv venv
source venv/bin/activate

# Install ChronoSight
pip install .

# Verifikasi instalasi
chronosight --version
```

Untuk mode pengembangan (editable):

```bash
pip install -e .
```

### Konfigurasi API Key

```bash
# Cara 1: Environment variable (direkomendasikan)
export GEMINI_API_KEY="api-key-anda-di-sini"

# Cara 2: Lewat argumen CLI langsung
chronosight -t /path/ke/direktori -k "api-key-anda-di-sini"
```

## 📖 Cara Penggunaan

### Scan Dasar dengan Analisis AI

```bash
chronosight -t /var/log
```

### Scan Tanpa AI (Hanya Ekstraksi Metadata)

```bash
chronosight -t /home/user/Downloads --no-ai
```

### Tentukan Lokasi Output File JSON

```bash
chronosight -t /tmp -o /evidence/kasus001/timeline.json
```

### Simpan Laporan Analisis AI ke File

```bash
chronosight -t /var/log --save-analysis /evidence/kasus001/analisis.md
```

### Tentukan Model Gemini Tertentu

```bash
chronosight -t /etc -m gemini-2.5-pro
```

### Contoh Lengkap Satu Perintah

```bash
export GEMINI_API_KEY="AIza..."
chronosight \
    --target /home/tersangka/Documents \
    --output timeline_kasus.json \
    --save-analysis laporan_analisis.md \
    --model gemini-3.6-flash
```

---

## 💽 Penggunaan dengan File Disk Image (`.dd`)

ChronoSight bekerja di tingkat **filesystem / direktori**. Untuk memindai file `.dd` (raw disk image), Anda harus terlebih dahulu **me-mount** file tersebut ke sebuah direktori lokal, kemudian arahkan ChronoSight ke direktori mount tersebut.

> **⚠️ Selalu mount disk image secara read-only (`ro`) untuk menjaga integritas bukti forensik dan mencegah perubahan data yang tidak disengaja.**

---

### Langkah 1 — Menentukan Jenis Partisi (Tunggal atau Multi)

Sebelum melakukan mount, Anda harus mengetahui apakah file `.dd` merupakan:
- **Single-Partition Image** — dump langsung dari satu filesystem (contoh: hanya `/dev/sda1`)
- **Full Disk Image** — dump dari seluruh harddisk yang mengandung tabel partisi MBR/GPT berisi beberapa partisi (contoh: `/dev/sda`)

Gunakan **salah satu** metode berikut:

#### Metode A: Perintah `file` (Paling Cepat)

```bash
file /path/ke/evidence.dd
```

| Output Mengandung | Artinya | Tindakan |
|---|---|---|
| `ext4 filesystem`, `NTFS`, `FAT32`, `XFS`, dll. | **Single Partition** | Mount langsung dengan `loop` |
| `DOS/MBR boot sector`, `GUID Partition Table (GPT)` | **Full Disk / Multi-Partisi** | Gunakan `kpartx` atau `losetup` |

**Contoh output:**

```text
# Single Partition (filesystem terdeteksi langsung)
evidence.dd: Linux rev 1.0 ext4 filesystem data, UUID=3a1b2c3d-...

# Full Disk / Multi-Partisi (tabel partisi terdeteksi)
evidence.dd: DOS/MBR boot sector; partition 1 : ID=0x83, start-CHS ...
evidence.dd: GUID Partition Table (GPT), ...
```

---

#### Metode B: `fdisk -l` (Paling Informatif)

```bash
fdisk -l /path/ke/evidence.dd
```

**Output Single Partition** — `fdisk` memberi peringatan bahwa tidak ada tabel partisi yang valid:
```text
Disk evidence.dd doesn't contain a valid partition table.
```
> Ini **bukan** error. Artinya file image tersebut adalah dump dari satu partisi filesystem saja, tanpa header MBR/GPT.

**Output Multi-Partisi** — `fdisk` menampilkan daftar partisi:
```text
Disk evidence.dd: 64 GiB, 68719476736 bytes, 134217728 sectors
Disklabel type: gpt

Device            Start       End   Sectors  Size Type
evidence.dd1       2048   1050623   1048576  512M EFI System
evidence.dd2    1050624   9439231   8388608    4G Linux swap
evidence.dd3    9439232  41943039  32503808 15.5G Linux filesystem  ← target
```

---

#### Metode C: `parted` (Detail Partisi)

```bash
parted /path/ke/evidence.dd print
```

- **Single Partition** → menghasilkan pesan `unrecognised disk label`
- **Multi-Partisi** → menampilkan tabel lengkap dengan kolom `Number`, `Start`, `End`, `File system`, `Flags`

---

#### Metode D: `mmls` (Sleuth Kit — Standar Forensik)

```bash
mmls /path/ke/evidence.dd
```

`mmls` dari The Sleuth Kit adalah tool standar forensik untuk memetakan layout volume, offset sektor, dan batas partisi. Sudah tersedia di Kali Linux. Untuk distro lain instal via: `sudo apt install sleuthkit`.

---

### Ringkasan Keputusan

```
Jalankan: file evidence.dd
        │
        ├── Menampilkan "ext4 / NTFS / FAT32 / XFS ..."
        │         → SINGLE PARTITION
        │         → Lanjut ke: Mount (Single Partition)
        │
        └── Menampilkan "DOS/MBR boot sector" atau "GPT"
                  → FULL DISK / MULTI-PARTISI
                  → Lanjut ke: Mount (Multi-Partisi)
```

---

### Langkah 2A — Mount Single-Partition Image

```bash
# 1. Buat direktori mount point
sudo mkdir -p /mnt/forensik

# 2. Mount secara read-only menggunakan loop device
sudo mount -o ro,loop /path/ke/evidence.dd /mnt/forensik

# 3. Verifikasi isi direktori
ls /mnt/forensik

# 4. Jalankan ChronoSight
chronosight -t /mnt/forensik -o timeline_kasus.json --save-analysis laporan_analisis.md

# 5. Unmount setelah selesai
sudo umount /mnt/forensik
```

---

### Langkah 2B — Mount Multi-Partition (Full Disk) Image

```bash
# 1. Install kpartx (jika belum ada)
sudo apt install kpartx -y           # Debian / Ubuntu / Kali Linux
# sudo pacman -S multipath-tools     # Arch Linux

# 2. Petakan semua partisi secara read-only (flag -r)
sudo kpartx -av -r /path/ke/evidence.dd
# Contoh output:
#   add map loop0p1 (253:0): 0 1048576 linear /dev/loop0 2048
#   add map loop0p2 (253:1): 0 8388608 linear /dev/loop0 1050624
#   add map loop0p3 (253:2): 0 32503808 linear /dev/loop0 9439232

# 3. Lihat daftar device yang sudah dipetakan
ls /dev/mapper/
# → loop0p1  loop0p2  loop0p3

# 4. Buat direktori mount point
sudo mkdir -p /mnt/forensik

# 5. Mount partisi target (contoh: loop0p3 = Linux filesystem)
sudo mount -o ro /dev/mapper/loop0p3 /mnt/forensik

# 6. Verifikasi isi direktori
ls /mnt/forensik

# 7. Jalankan ChronoSight
chronosight -t /mnt/forensik -o timeline_kasus.json --save-analysis laporan_analisis.md

# 8. Unmount dan bersihkan device setelah selesai
sudo umount /mnt/forensik
sudo kpartx -d /path/ke/evidence.dd
```

---

### Alternatif: Ekstrak File Tanpa Mount (SleuthKit)

Gunakan metode ini jika filesystem rusak/korup atau tidak bisa di-mount secara langsung:

```bash
# Install SleuthKit
sudo apt install sleuthkit -y

# Ekstrak semua file dari image .dd ke folder lokal
tsk_recover -e /path/ke/evidence.dd /home/user/file_terekstrak/

# Scan folder hasil ekstraksi dengan ChronoSight
chronosight -t /home/user/file_terekstrak/ -o timeline_kasus.json
```

---

## 🖥️ Referensi Argumen CLI

| Flag | Deskripsi | Default |
|---|---|---|
| `-t`, `--target` | **(Wajib)** Direktori yang akan dipindai | — |
| `-k`, `--api-key` | API Key Gemini (atau gunakan env var `GEMINI_API_KEY`) | `$GEMINI_API_KEY` |
| `-o`, `--output` | Path file output JSON timeline | `chronosight_timeline.json` |
| `-m`, `--model` | Model Gemini yang digunakan | `gemini-3.6-flash` |
| `--no-ai` | Lewati analisis AI, hanya ekstrak & buat timeline | `false` |
| `--save-analysis` | Simpan laporan analisis AI ke file Markdown | — |
| `-v`, `--version` | Tampilkan versi dan keluar | — |

## 🏗️ Struktur Proyek

```
chronosight/
├── chronosight/
│   ├── __init__.py       # Metadata paket
│   ├── main.py           # Entry point CLI & orkestrasi pipeline
│   ├── extractor.py      # Ekstraksi metadata forensik (MAC times, hash)
│   ├── timeline.py       # Timeline builder kronologis & exporter JSON
│   ├── analyzer.py       # Integrasi Gemini AI & analisis forensik
│   └── ui.py             # Tema terminal Rich, tabel & helper tampilan
├── setup.py              # Installer paket (pip install .)
├── requirements.txt      # Dependensi Python
├── LICENSE               # Lisensi MIT
├── .gitignore
└── README.md
```

## 🔬 Cara Kerja

```
┌─────────────┐     ┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│   Target     │────▶│  Forensic    │────▶│   Timeline   │────▶│   Gemini AI  │
│  Direktori   │     │  Extractor   │     │   Builder    │     │   Analyzer   │
│  /mnt/forensik│    │ MAC Times    │     │ Kronologis   │     │ Deteksi      │
│  /var/log    │     │ MD5/SHA-256  │     │ Sort JSON    │     │ Anomali      │
│  /home/...   │     │ Ukuran File  │     │ Event Stream │     │ Hunting IOC  │
└─────────────┘     └──────────────┘     └──────────────┘     └──────────────┘
```

1. **Ekstraksi** — Menelusuri direktori target secara rekursif, mengumpulkan MAC timestamp, ukuran file, tipe file, dan menghitung hash MD5/SHA-256 untuk integritas forensik.
2. **Pembangunan Timeline** — Mengekspansi setiap file menjadi tiga event (Modified, Accessed, Created) dan mengurutkannya secara kronologis.
3. **Analisis AI** — Timeline JSON dikirim ke Gemini dengan system prompt investigator forensik yang mengidentifikasi pola mencurigakan, memberikan peringkat severity, dan merekomendasikan langkah selanjutnya.

## 🔒 Keamanan & Privasi

- **Local-first** — Seluruh pemindaian dan hashing dilakukan secara lokal. Tidak ada konten file yang dikirim ke layanan eksternal.
- **Hanya Metadata** — Yang dikirim ke Gemini API hanyalah metadata (path file, timestamp, ukuran, hash). **Konten file tidak pernah dikirim.**
- **Forensik Read-Only** — Selalu mount disk image dengan `-o ro` untuk mencegah modifikasi bukti.
- **Keamanan API Key** — Gunakan environment variable, jangan hardcode API key di dalam perintah.

## 🤝 Kontribusi

Kontribusi sangat disambut! Silakan:

1. Fork repositori ini
2. Buat feature branch (`git checkout -b fitur/fitur-keren`)
3. Commit perubahan Anda (`git commit -m 'Tambah fitur keren'`)
4. Push ke branch (`git push origin fitur/fitur-keren`)
5. Buka Pull Request

## ⚠️ Pernyataan Hukum (Disclaimer)

> **ChronoSight disediakan hanya untuk tujuan edukasi dan penelitian keamanan yang telah mendapat otorisasi resmi.**
>
> Tool ini dirancang untuk membantu investigator forensik digital dan tim incident response dalam pekerjaan yang sah. Pengguna sepenuhnya bertanggung jawab untuk memastikan mereka memiliki izin yang tepat sebelum memindai sistem atau direktori apapun.
>
> Para pengembang tidak bertanggung jawab atas penyalahgunaan tool ini. Selalu dapatkan izin tertulis sebelum melakukan analisis forensik pada sistem yang bukan milik Anda.
>
> Hasil analisis AI bersifat **advisory (rekomendasi pendukung)** — selalu verifikasi temuan melalui investigasi manual dan prosedur forensik yang mapan sebelum mengambil kesimpulan atau tindakan.

## 📄 Lisensi

Proyek ini dilisensikan di bawah Lisensi MIT — lihat file [LICENSE](LICENSE) untuk detailnya.

---

<p align="center">
  <b>⟐ ChronoSight</b> — <i>See through time. Find the truth.</i><br>
  <i>Lihat menembus waktu. Temukan kebenaran.</i>
</p>
