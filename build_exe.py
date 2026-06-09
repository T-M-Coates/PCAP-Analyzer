#!/usr/bin/env python3
"""
build_exe.py — PyInstaller build helper for PCAP Analyzer
==========================================================

Produces a self-contained Windows executable in:
    dist/PCAPAnalyzer/PCAPAnalyzer.exe

Run it once, then distribute the entire dist/PCAPAnalyzer/ folder.
The exe creates its uploads/ and data/ directories next to itself,
so analysis results persist between runs.

Usage
-----
    pip install pyinstaller          # one-time
    python build_exe.py

Output
------
    dist/
    └── PCAPAnalyzer/
        ├── PCAPAnalyzer.exe        ← run this
        ├── templates/              (bundled by --add-data)
        ├── static/                 (bundled by --add-data)
        ├── .env.example            (copied in by this script)
        └── _internal/              (PyInstaller support files)

Notes
-----
* We use --onedir (not --onefile) so that Flask can find its
  templates/ and static/ directories at runtime, and so that the
  uploads/ and data/ folders created next to the exe persist
  between runs.  A --onefile build would unpack to a temp directory
  that is wiped on every restart, losing your analysis history.

* If PyInstaller is not installed this script will try to install it
  automatically via pip.
"""
from __future__ import annotations
import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


def _ensure_pyinstaller() -> None:
    try:
        import PyInstaller  # noqa: F401
    except ImportError:
        print("PyInstaller not found — installing…")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "pyinstaller"])


def _clean(path: str) -> None:
    """Remove a directory tree if it exists."""
    if os.path.isdir(path):
        shutil.rmtree(path)


def build() -> None:
    _ensure_pyinstaller()
    import PyInstaller.__main__  # noqa: E402  (import after ensure)

    dist_dir  = os.path.join(HERE, "dist")
    build_dir = os.path.join(HERE, "build")
    spec_file = os.path.join(HERE, "PCAPAnalyzer.spec")

    # Clean previous build artefacts
    _clean(dist_dir)
    _clean(build_dir)
    if os.path.exists(spec_file):
        os.remove(spec_file)

    # ── Collect hidden imports ────────────────────────────────────
    # Modules that PyInstaller's static analysis might miss because
    # they are imported inside functions or behind try/except.
    hidden = [
        "dpkt",
        "dpkt.pcap",
        "dpkt.pcapng",
        "dpkt.ethernet",
        "dpkt.ip",
        "dpkt.tcp",
        "dpkt.udp",
        "dpkt.dns",
        "dpkt.http",
        "database",
        "analyzer",
        "analyzer.runner",
        "analyzer.meta",
        "analyzer.hosts",
        "analyzer.dns",
        "analyzer.http",
        "analyzer.beaconing",
        "analyzer.smb",
        "analyzer.iocs",
        "analyzer.utils",
        "enrichment",
        "enrichment.virustotal",
        "enrichment.geoip",
        "enrichment.whois",
        "enrichment.abuseipdb",
        "export",
        "export.html_export",
        "export.csv_export",
        "flask",
        "werkzeug",
        "dotenv",
        "requests",
        "ipaddress",
        "sqlite3",
    ]

    hidden_args = []
    for h in hidden:
        hidden_args += ["--hidden-import", h]

    # ── Data files (src;dst relative to bundle root) ──────────────
    add_data = [
        f"{os.path.join(HERE, 'templates')};templates",
        f"{os.path.join(HERE, 'static')};static",
        f"{os.path.join(HERE, '.env.example')};.",
    ]

    add_data_args = []
    for d in add_data:
        add_data_args += ["--add-data", d]

    # ── PyInstaller invocation ────────────────────────────────────
    args = [
        os.path.join(HERE, "app.py"),
        "--name=PCAPAnalyzer",
        "--onedir",                  # see module docstring for why not --onefile
        "--console",                 # keep console so log output is visible
        f"--distpath={dist_dir}",
        f"--workpath={build_dir}",
        f"--specpath={HERE}",
        "--noconfirm",
        "--clean",
    ] + hidden_args + add_data_args

    print("\n=== Running PyInstaller ===")
    PyInstaller.__main__.run(args)

    # ── Post-build: copy .env.example next to the exe if missing ──
    dest_env = os.path.join(dist_dir, "PCAPAnalyzer", ".env.example")
    src_env  = os.path.join(HERE, ".env.example")
    if not os.path.exists(dest_env) and os.path.exists(src_env):
        shutil.copy(src_env, dest_env)

    exe_path = os.path.join(dist_dir, "PCAPAnalyzer", "PCAPAnalyzer.exe")
    print("\n=== Build complete ===")
    if os.path.exists(exe_path):
        size_mb = os.path.getsize(exe_path) / 1_048_576
        print(f"  Executable : {exe_path}")
        print(f"  Size       : {size_mb:.1f} MB")
        print("\nTo run:")
        print(f'  cd "{os.path.join(dist_dir, "PCAPAnalyzer")}"')
        print("  PCAPAnalyzer.exe")
    else:
        print("  WARNING: exe not found — check PyInstaller output above.")


if __name__ == "__main__":
    build()
