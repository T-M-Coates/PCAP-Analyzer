# PCAP Analyzer

A locally-hosted Python web app that ingests `.pcap` network captures and
produces an interactive, browser-based threat analysis report.
**No data ever leaves your machine.**

---

## What it does

Upload a PCAP file and get an instant eight-tab report covering:

| Tab | What you see |
|-----|-------------|
| **Overview** | Protocol pie chart · top senders bar chart · severity summary cards · key-event timeline |
| **Hosts** | Every IP classified as internal/external · packets sent/received · GeoIP country · ASN |
| **DNS** | All queries with resolved IPs · flagged domains (suspicious TLDs, DGA hex32 patterns, high-frequency beaconing indicators) |
| **HTTP** | Every HTTP request · flagged paths/UAs · expandable detail rows · decoded Base64 URL parameters (UTF-8 + UTF-16LE) |
| **Beaconing** | Flows flagged by Coefficient of Variation analysis · regularity progress bars |
| **SMB** | TCP 139/445 pairs · DC candidate · external SMB alerts |
| **IOCs** | Unified indicator list (CRITICAL / HIGH / MEDIUM / INFO) with VirusTotal scores, KNOWN C2 badges, country flags — sortable, copyable, exportable |
| **History** | All past analyses stored in SQLite — view any previous report, delete records |

Export options (header **Export** dropdown):
- **Full Report (HTML)** — single self-contained file with all CSS/JS inlined, works offline
- **IOCs (TXT)** — plain-text indicator list for pasting into tickets
- **IOCs (CSV)** — spreadsheet-ready with VT scores, country, ASN columns

---

## Requirements

- **Python 3.9 or newer** — [python.org/downloads](https://www.python.org/downloads/)
- Windows 10/11 (Linux/macOS work too, but `run.bat` is Windows-only)
- Internet access on first run to download the Feodo Tracker C2 blocklist
  and CDN resources for the offline HTML export (optional)

---

## Quick start (Windows)

1. **Download / clone** this folder somewhere on your machine.

2. **Double-click `run.bat`**

   The script will:
   - Verify Python 3.9+ is on `PATH`
   - Create a `.venv` virtual environment (first run only)
   - Install all Python dependencies
   - Copy `.env.example` → `.env` (first run only)
   - Start the Flask server and open `http://127.0.0.1:5000` in your browser

3. **Drop a `.pcap` file** onto the upload zone and click **Analyze**.

---

## Manual start (Linux / macOS)

```bash
cd pcap-analyzer/

# Create & activate virtualenv
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Copy config template
cp .env.example .env

# Start
python app.py
```

Then open [http://127.0.0.1:5000](http://127.0.0.1:5000).

---

## Configuration (`.env`)

| Variable | Default | Purpose |
|----------|---------|---------|
| `SECRET_KEY` | `change-me-in-production` | Flask session signing key — set to a long random string |
| `VT_API_KEY` | *(empty)* | VirusTotal API key — see section below |
| `MAX_UPLOAD_MB` | `200` | Maximum PCAP upload size in megabytes |

---

## VirusTotal integration (optional)

The IOC tab can show how many antivirus engines flag each IP and domain.

1. Create a free account at [virustotal.com](https://www.virustotal.com/)
2. Go to **Profile → API Key**
3. Copy your key into `.env`:
   ```
   VT_API_KEY=your_key_here
   ```
4. Restart the server.

> **Rate limiting:** The free tier allows 4 requests/minute. The app
> automatically throttles VT calls and caches results for 24 hours so you
> won't exhaust your quota on repeated analyses.

---

## GeoIP country lookup (optional)

Host and IOC tables show country flags when a MaxMind database is present.

1. Create a free account at [maxmind.com](https://www.maxmind.com/en/geolite2/signup)
2. Download **GeoLite2-Country** (`.mmdb` format)
3. Place the file at:
   ```
   pcap-analyzer/data/GeoLite2-Country.mmdb
   ```

The app detects the file on startup — no restart needed once it's in place.
If the file is absent, country columns show `—` without any error.

---

## C2 blocklists (automatic, no setup needed)

On each first analysis of the day the app downloads two free blocklists:

| List | Source |
|------|--------|
| Feodo Tracker | `feodotracker.abuse.ch` |
| CINS Army | `cinsscore.com` |

IPs matching either list receive a **KNOWN C2** badge and their severity
is automatically upgraded by one level. Lists are cached for 24 hours.
If the download fails the app continues without C2 checking (no error shown).

---

## Building a standalone executable (optional)

> **Requires:** `pip install pyinstaller`

```bash
python build_exe.py
```

Output: `dist/PCAPAnalyzer/PCAPAnalyzer.exe`

Run the exe from its folder — analysis data (`uploads/`, `data/`) is stored
alongside it and persists between runs.

---

## Project structure

```
pcap-analyzer/
├── app.py              Flask application + all routes
├── config.py           Settings (loaded from .env)
├── database.py         SQLite history wrapper
├── run.bat             Windows one-click launcher
├── build_exe.py        PyInstaller build helper
├── requirements.txt
├── .env                Local config (gitignored)
├── .env.example        Config template
│
├── analyzer/           Core PCAP analysis engine
│   ├── runner.py       Orchestrator (single-pass packet loop)
│   ├── meta.py         Capture metadata
│   ├── hosts.py        IP inventory & classification
│   ├── dns.py          DNS query parsing & flagging
│   ├── http.py         HTTP request parsing & flagging
│   ├── beaconing.py    Beaconing detection via CV analysis
│   ├── smb.py          SMB traffic analysis
│   ├── iocs.py         IOC aggregation & severity scoring
│   └── utils.py        Shared helpers
│
├── enrichment/         Optional external lookups
│   ├── virustotal.py   VirusTotal API v3
│   ├── geoip.py        MaxMind GeoLite2 country lookup
│   ├── whois.py        ASN/WHOIS via ipwhois
│   └── abuseipdb.py    Feodo Tracker + CINS C2 blocklists
│
├── export/             Export helpers
│   ├── html_export.py  Self-contained offline HTML
│   └── csv_export.py   IOC → CSV
│
├── templates/          Jinja2 HTML templates
├── static/             CSS + JavaScript
│
├── uploads/            Uploaded PCAPs (auto-created, gitignored)
└── data/               Results JSON + SQLite DB (auto-created, gitignored)
```

---

## Notes

- Tested with Python 3.9, 3.10, 3.11, 3.12, 3.13
- The server binds to `127.0.0.1` only — it is not accessible from other machines
- All processing is synchronous in a background thread; the browser polls for progress
- Large PCAPs (100 MB+) may take 30–60 seconds to analyse
- The `geoip2` and `ipwhois` packages in `requirements.txt` are optional;
  the app installs and runs fine without them (enrichment columns show `—`)
- This app has been made by Anthropic - Claude Code as an experiment to see how far we can analyse PCAP files. Some information returned may be factually incorrect.
