# ⚡ ChronoSight v2.0 ⚡
**AI-Powered Deep Forensic Artifact & Case Investigator**

![Python Version](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Platform](https://img.shields.io/badge/platform-Linux-orange)

ChronoSight v2.0 is a next-generation, open-source CLI digital forensics tool for Linux. It goes beyond simple timeline extraction by performing **deep, format-specific metadata extraction** and leveraging **Google Gemini AI** to produce comprehensive Digital Forensics and Incident Response (DFIR) case analysis reports in Indonesian.

## 🚀 Key Features

* **Deep Metadata Extraction**:
  * **Images**: Extracts EXIF data, original capture timestamps, camera info, and GPS coordinates (identifies physical locations and manipulated images).
  * **PDFs**: Extracts author attribution, creation/modification dates, and text previews (detects hidden content and encryption).
  * **Spreadsheets (.xlsx)**: Detects `hidden` and `veryHidden` sheets (strong indicators of anti-forensics or data concealment).
  * **Word Documents (.docx)**: Extracts revision history and author metadata.
  * **Text & Logs**: Previews content from scripts, logs, and CSVs to identify covert communications or suspicious entries.
* **Forensic Integrity**: Automatically computes MD5 and SHA-256 hashes for all extracted files to maintain a strict chain of custody.
* **AI DFIR Engine**: Utilizes Google's Gemini AI (`gemini-3.6-flash` default, using the modern `google-genai` SDK) to analyze the extracted evidence against your investigation scenario.
* **Hacker-Themed UI**: Built with `rich` for a beautiful, responsive, and color-coded terminal experience highlighting critical forensic flags.

---

## 🛠️ Installation Guide

ChronoSight v2.0 is designed for Linux environments (Ubuntu, Kali, Debian, Arch).

### 1. Clone the Repository
```bash
git clone https://github.com/yourusername/chronosight.git
cd chronosight
```

### 2. Create a Virtual Environment (Recommended)
```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install the Package
Install ChronoSight and its dependencies globally (or within your venv):
```bash
pip install .
```
*Note: For development mode, use `pip install -e .`*

Verify installation:
```bash
chronosight --version
```

---

## 📖 Usage & Examples

### Basic Metadata Extraction (No AI)
If you only want to scan a directory and view the forensic flags in the terminal without sending data to the AI:
```bash
chronosight -t /path/to/extracted/evidence --no-ai
```

### AI-Powered DFIR Analysis
To generate a full case report, you must provide your Google Gemini API Key. You can set it as an environment variable or pass it via the CLI.

**Method 1: Environment Variable (Recommended)**
```bash
export GEMINI_API_KEY="your_api_key_here"
chronosight -t /mnt/usb_evidence
```

**Method 2: CLI Argument**
```bash
chronosight -t /mnt/usb_evidence -k "your_api_key_here"
```

### Using an Investigation Scenario
You can guide the AI's analysis by providing a specific investigation scenario or a list of questions.

**Passing a scenario directly:**
```bash
chronosight -t /home/suspect/Downloads -s "Look for evidence of data exfiltration to a cloud provider on August 15th."
```

**Passing a scenario file and exporting the report:**
Create a file named `scenario.txt`:
> "Suspek diduga telah membocorkan data keuangan perusahaan. Analisis artefak untuk menemukan bukti akses tidak sah pada dokumen Excel, dan periksa apakah ada data yang disembunyikan menggunakan fitur hidden sheet."

Run the tool and save the output to a Markdown file:
```bash
chronosight -t /mnt/evidence_disk -s scenario.txt -o case_042_report.md
```

---

## ⚠️ Disclaimer & Legal

**For Authorized Use Only.**
ChronoSight is an open-source tool intended solely for authorized digital forensics investigations, incident response, and cybersecurity research. 

- The developers assume no liability for misuse, unauthorized access, or damage caused by this tool.
- **AI Limitations**: The AI-generated DFIR reports are meant to assist human investigators, not replace them. Always manually verify critical forensic findings (hashes, timestamps, hidden sheets) before presenting them in a court of law or official proceedings. AI models can hallucinate or misinterpret metadata.

---

## 📄 License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
