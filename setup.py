"""
setup.py — ChronoSight Package Installer.

Allows the tool to be installed globally or in a virtual environment via:
    pip install .
    pip install -e .   # editable / development mode

After installation the ``chronosight`` command is available system-wide.
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read the README for the long description on PyPI.
this_dir = Path(__file__).parent
long_description = (this_dir / "README.md").read_text(encoding="utf-8")

setup(
    name="chronosight",
    version="1.0.0",
    author="ChronoSight Contributors",
    description=(
        "AI-Powered Digital Artifact Timeline Extractor — "
        "forensic metadata extraction and Gemini AI anomaly analysis."
    ),
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/chronosight",
    license="MIT",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: Developers",
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
        "Topic :: Utilities",
    ],
    python_requires=">=3.10",
    packages=find_packages(),
    install_requires=[
        "rich>=13.0.0",
        "google-genai>=2.3.0",
    ],
    entry_points={
        "console_scripts": [
            "chronosight=chronosight.main:main",
        ],
    },
    keywords=[
        "forensics",
        "timeline",
        "cybersecurity",
        "gemini",
        "ai",
        "incident-response",
        "dfir",
        "malware-analysis",
    ],
)
