# ⚡ ChronoSight v2.0 ⚡
**AI-Powered Deep Forensic Artifact & Case Investigator**

![Python Version](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Platform](https://img.shields.io/badge/platform-Linux-orange)

*(🇮🇩 Panduan Bahasa Indonesia tersedia di bagian bawah / Indonesian guide is available below)*

ChronoSight v2.0 is a next-generation, open-source CLI digital forensics tool for Linux. It goes beyond simple timeline extraction by performing **deep, format-specific metadata extraction** and leveraging **Google Gemini AI** to produce comprehensive Digital Forensics and Incident Response (DFIR) case analysis reports in Indonesian.

## 🚀 Key Features

* **Deep Format-Specific Metadata Extraction**:
  * **Images**: Extracts EXIF data, original capture timestamps, camera info, and GPS coordinates (identifies physical locations and manipulated images).
  * **PDFs**: Extracts author attribution, creation/modification dates, and text previews.
  * **Word Documents (.docx)**: Extracts revision history, author metadata, and content previews.
* **Covert & Hidden Data Detection**:
  * Explicitly detects `hidden` and `veryHidden` sheets in Excel (`.xlsx`) which are strong indicators of anti-forensics or data concealment.
  * Identifies suspicious text files (e.g. binaries disguised with text extensions).
* **Forensic Integrity & Chain of Custody**:
  * Automatically calculates **MD5** and **SHA-256** cryptographic hashes for every extracted file.
  * Preserves original filesystem MAC (Modified, Accessed, Created) timestamps.
* **AI-Powered DFIR Engine**:
  * Integrates with Google's modern `google-genai` SDK (`gemini-3.6-flash`).
  * Analyzes all extracted artifacts against your specific investigation scenario.
  * Outputs a structured, professional DFIR report with evidence tables, answers to investigative questions, risk assessment, and forensic conclusions.
* **Hacker-Themed UI**: Built with `rich` for a beautiful, responsive, and color-coded terminal experience highlighting critical forensic flags.

---

## 🛠️ Installation Guide

### 1. Clone the Repository
```bash
git clone https://github.com/SallVea/chronosight.git
cd chronosight
```

### 2. Install the Package
It is recommended to use a virtual environment.
```bash
python3 -m venv venv
source venv/bin/activate
pip install .
```

Verify installation:
```bash
chronosight --version
```

---

## 💽 Working with Disk Image Files (.dd)

In digital forensics, evidence is often acquired as raw disk images (`.dd`, `.img`, or `.raw`). Before ChronoSight can scan the files, you must mount the image as a local directory on your Linux system.

### Step 1: Check the Partition Type (Single vs. Multi)
Run the `file` or `fdisk` command:
```bash
file evidence.dd
fdisk -l evidence.dd
```

**How to read the result:**
* **Single Partition:** If the output says `DOS/MBR boot sector, OEM-ID "mkfs.fat"` or `ext4 filesystem data`. Proceed to **Step 2A**.
* **Multi-Partition:** If the output shows a partition table (`Device Start End Sectors...`). Proceed to **Step 2B**.

### Step 2A: Mounting a Single Partition `.dd`
Mount it directly using a loop device in Read-Only (`ro`) mode to preserve forensic integrity.
```bash
sudo mkdir -p /mnt/forensic_usb
sudo mount -o ro,loop evidence.dd /mnt/forensic_usb/
ls -l /mnt/forensic_usb/
```

### Step 2B: Mounting a Multi-Partition `.dd`
Map the individual partitions using `kpartx`.
```bash
sudo apt install kpartx
sudo kpartx -av -r evidence.dd
# Note the loop map name (e.g., loop0p1)

sudo mkdir -p /mnt/forensic_disk1
sudo mount -o ro /dev/mapper/loop0p1 /mnt/forensic_disk1/
```

### Step 3: Running ChronoSight on the Mounted Image
**Basic Scan (No AI):**
```bash
chronosight -t /mnt/forensic_usb --no-ai
```

**Full AI DFIR Analysis with a Scenario:**
```bash
export GEMINI_API_KEY="your_api_key_here"
chronosight -t /mnt/forensic_usb -s "Look for evidence of hidden financial records." -o report.md
```

---
---

# 🇮🇩 Panduan Bahasa Indonesia

ChronoSight v2.0 adalah alat forensik digital CLI berbasis Linux sumber terbuka. Alat ini melampaui ekstraksi linimasa biasa dengan melakukan ekstraksi metadata mendalam spesifik format, serta menggunakan **Google Gemini AI** untuk menghasilkan laporan analisis insiden (DFIR) terstruktur.

## 🚀 Fitur Utama

* **Ekstraksi Metadata Mendalam Spesifik Format**:
  * **Gambar**: Ekstraksi EXIF, koordinat GPS, tanggal jepret asli, dan info perangkat (mendeteksi gambar yang diedit atau lokasi fisik).
  * **PDF**: Ekstraksi penulis dokumen, tanggal buat/ubah, dan pratinjau teks.
  * **Word (.docx)**: Ekstraksi riwayat revisi dan penulis.
* **Deteksi Data Tersembunyi (Anti-Forensik)**:
  * Mendeteksi secara spesifik lembar `hidden` dan `veryHidden` pada Excel (`.xlsx`) yang sering digunakan untuk menyembunyikan muatan eksfiltrasi data.
  * Mengidentifikasi anomali ekstensi (file biner yang disamarkan sebagai file teks).
* **Integritas Forensik (Chain of Custody)**:
  * Penghitungan otomatis hash **MD5** dan **SHA-256** untuk menjamin integritas barang bukti.
  * Ekstraksi MAC Times (Waktu Modifikasi, Akses, dan Pembuatan) dari *filesystem*.
* **Mesin Analisis Kasus Berbasis AI**:
  * Terintegrasi dengan SDK Google terbaru (`gemini-3.6-flash`).
  * Mampu menganalisis seluruh metadata artefak dan menjawab Skenario Investigasi yang Anda berikan.
  * Menghasilkan laporan Markdown terstruktur yang berisi tabel bukti kunci, evaluasi risiko, validasi chain-of-custody, dan kesimpulan.
* **Antarmuka Terminal Hacker**: UI interaktif menggunakan pustaka `rich` dengan indikator *flag* forensik berwarna (seperti 🚨 VERY HIDDEN atau 📍 GPS).

---

## 🛠️ Panduan Instalasi
```bash
git clone https://github.com/SallVea/chronosight.git
cd chronosight
python3 -m venv venv
source venv/bin/activate
pip install .
```

---

## 💽 Menangani Berkas Disk Image Forensik (.dd)

Dalam investigasi forensik, bukti digital sering kali didapatkan dalam bentuk raw disk image (`.dd`, `.img`). Anda harus me-*mount* (mengaitkan) file tersebut menjadi sebuah direktori di Linux sebelum dipindai.

### Langkah 1: Cek Tipe Partisi (Tunggal vs. Multi-Partisi)
Gunakan perintah `file` atau `fdisk`:
```bash
file bukti.dd
fdisk -l bukti.dd
```

**Cara membaca hasilnya:**
* **Partisi Tunggal (Single):** Jika hasilnya menunjukkan `DOS/MBR boot sector` (Flashdisk/FAT32) atau `ext4 data`. Lanjut ke **Langkah 2A**.
* **Multi-Partisi:** Jika muncul tabel struktur partisi yang panjang (Hardisk/GPT/MBR). Lanjut ke **Langkah 2B**.

### Langkah 2A: Mounting File `.dd` Partisi Tunggal
Gunakan *loop device*. ⚠️ **PENTING**: Selalu gunakan mode Read-Only (`ro`).
```bash
sudo mkdir -p /mnt/forensik_usb
sudo mount -o ro,loop bukti.dd /mnt/forensik_usb/
ls -l /mnt/forensik_usb/
```

### Langkah 2B: Mounting File `.dd` Multi-Partisi
Gunakan `kpartx` untuk memetakan isi tabel partisi.
```bash
sudo apt install kpartx -y
sudo kpartx -av -r bukti.dd
# Perhatikan nama loop map yang muncul (misal: loop0p1)

sudo mkdir -p /mnt/forensik_partisi1
sudo mount -o ro /dev/mapper/loop0p1 /mnt/forensic_partisi1/
```
*(Untuk melepasnya: `sudo umount /mnt/forensic_partisi1` lalu `sudo kpartx -dv bukti.dd`)*

### Langkah 3: Menggunakan ChronoSight pada Direktori Hasil Mount
**Pemindaian Dasar (Tanpa AI):**
```bash
chronosight -t /mnt/forensik_usb --no-ai
```

**Analisis Forensik AI Penuh dengan Skenario:**
```bash
export GEMINI_API_KEY="AIzaSy_Token_Anda_Disini"
chronosight -t /mnt/forensik_usb -s "Apakah ada bukti manipulasi dokumen Excel atau eksfiltrasi data?" -o laporan_kasus_01.md
```

---

## ⚠️ Penafian (Disclaimer)
Alat ini dibuat khusus untuk keperluan investigasi forensik digital, respons insiden, dan penelitian keamanan siber yang sah secara hukum. 
- Laporan DFIR yang dihasilkan oleh AI ditujukan sebagai asisten penyidik, bukan pengganti analisis manusia. Selalu verifikasi temuan secara manual (terutama hash dan *hidden sheets*) sebelum menggunakannya sebagai barang bukti resmi.
- Pengembang tidak bertanggung jawab atas penyalahgunaan alat ini.

---
📄 **License**: MIT License
