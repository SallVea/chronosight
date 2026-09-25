"""
setup.py — ChronoSight v2.0 Package Installer.

Instal secara global atau dalam virtual environment:
    pip install .
    pip install -e .   # mode development (editable)

Setelah instalasi, perintah ``chronosight`` tersedia langsung dari terminal.
"""

from setuptools import setup, find_packages
from pathlib import Path

this_dir         = Path(__file__).parent
long_description = (this_dir / "README.md").read_text(encoding="utf-8")

setup(
    name="chronosight",
    version="2.0.0",
    author="ChronoSight Contributors",
    description=(
        "AI-Powered Deep Forensic Artifact & Case Investigator — "
        "ekstraksi EXIF/PDF/hidden-sheet/teks & laporan DFIR Bahasa Indonesia via Gemini AI."
    ),
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/SallVea/chronosight",
    license="MIT",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "Topic :: Security",
        "Topic :: System :: Filesystems",
    ],
    python_requires=">=3.10",
    packages=find_packages(),
    install_requires=[
        "rich>=13.0.0",
        "google-genai>=2.3.0",   # SDK modern (menggantikan google-generativeai yang deprecated)
        "Pillow>=10.0.0",
        "pypdf>=4.0.0",
        "openpyxl>=3.1.0",
        "python-docx>=1.1.0",
    ],
    entry_points={
        "console_scripts": [
            "chronosight=chronosight.main:main",
        ],
    },
    keywords=[
        "dfir", "forensics", "digital-forensics", "incident-response",
        "exif", "metadata", "gemini", "ai", "cybersecurity", "timeline",
        "malware-analysis", "hidden-sheet", "chain-of-custody",
    ],
)
