# VulnScan (desktop)

PySide6 desktop GUI for the FYP *Automated Vulnerability Scanner for Service Detection
and CVE Analysis with Suggested Mitigation*. Runs on Windows and Linux and packages
into a single executable with PyInstaller.

## Project layout
```
run_vulnscan.py          entry point
vulnscan.spec            PyInstaller build spec
requirements.txt
vulnscan/
  config.yaml            scan profiles, NVD/Gemini settings, limits (NFR-11)
  config.py              config loading, Nmap path resolution, admin check (NFR-08)
  validation.py          target validation, asset context cleaning (FR-13)
  pipeline.py            backends, scoring, confidence, coverage (FR-07..FR-20)
  engine/
    nmap_scanner.py      runs Nmap with live progress + cancel, parses XML (FR-01..04)
    nvd_client.py        CPE-first NVD matching, pacing, retries, cache (FR-05..12)
    mitigation.py        Gemini 2.5 Flash advice with JSON validation + fallback (FR-17)
    runner.py            orchestrates scan -> NVD -> risk -> mitigation
  storage.py             local SQLite scan history
  reports.py             PDF (ReportLab), HTML, JSON export (FR-19)
  gui/                   PySide6 screens: new scan, live progress, results, history
tests/test_core.py       offline unit tests (NFR-12)
```

## Run from source

**Windows (PowerShell)**
```powershell
py -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
py run_vulnscan.py
```

**Linux**
```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python run_vulnscan.py
```
On a minimal Linux install Qt may also need: `sudo apt install libxcb-cursor0`.

Pick the **Data source** on the New scan page: *Live scan* (Nmap + NVD + AI advice) or
*Demo data* (sample findings, no network traffic, labelled DEMO everywhere).

## First live scan
1. Install Nmap from https://nmap.org/download.html. On Windows tick "Add Nmap to PATH"
   and install **Npcap** when offered. The bottom bar should then show "Nmap 7.x".
2. Optional but recommended: set API keys (see below). Without an NVD key lookups are
   paced at one per 6 s; without a Gemini key findings get the static fallback advice.
3. Scan a machine in your lab (e.g. Metasploitable 2 on a host-only network) with the
   **Service detection** profile. Quick scan has no version detection, so nothing can be
   matched to CVEs, and the Coverage tab says so.
4. OS detection needs admin/root: run VulnScan as administrator (Windows) or with sudo.

How a live scan works:
- Nmap runs as a subprocess (no shell) with `--stats-every 5s`, so progress appears live
  and Cancel stops Nmap. Output is read from Nmap's XML, including CPE identifiers.
- Each service with a version is looked up in NVD by **CPE first** (`virtualMatchString`).
  If that finds nothing, a keyword search runs and those CVEs are marked lower
  confidence (`*`). Failed requests are retried, then reported as "not assessed",
  never as "no vulnerabilities".
- The highest-priority findings (default 15) get Gemini advice. Busy models (HTTP 429/503)
  are retried with backoff, then the next model in `gemini.models` is tried. Invalid or
  failed responses fall back to a static message pointing at the NVD record, and the
  reason is shown under the recommendation.
- If Gemini was busy, click **Retry AI advice** on the results screen later. It re-asks
  Gemini for the findings that only have fallback guidance, without re-scanning.

## Build the executable

PyInstaller can't cross-compile: build on Windows for the `.exe`, on Linux for the binary.
```bash
pip install pyinstaller
pyinstaller vulnscan.spec
```
Output: `dist/VulnScan.exe` (Windows) or `dist/VulnScan` (Linux). To override settings,
put an edited `config.yaml` next to the executable.

Nmap is not bundled. Users install it from https://nmap.org/download.html (on Windows tick
"Add Nmap to PATH"). VulnScan finds it via `nmap.path` in the config, the PATH, or the
default Windows install folders, and shows its status in the bottom bar.

## API keys (NFR-09)
Never put keys in code or `config.yaml`. Set environment variables instead:
```powershell
$env:NVD_API_KEY = "..."      # optional, faster NVD lookups
$env:GEMINI_API_KEY = "..."   # AI mitigation (engine backend)
```
```bash
export NVD_API_KEY=...; export GEMINI_API_KEY=...
```

To keep keys set permanently on Windows: `setx GEMINI_API_KEY "..."` (then open a new
terminal). Get keys from https://nvd.nist.gov/developers/request-an-api-key and
https://aistudio.google.com/apikey.

## Tests
```bash
python -m unittest discover -s tests -v
```
48 offline tests. The engine tests use a fake `nmap` executable and recorded-style NVD and
Gemini responses, so they need no network (NFR-12). The fake-Nmap tests are skipped on
Windows; run them on Linux or WSL.

## Changes from the original ai-mitigation branch
| Old module | Replaced by | Why |
|---|---|---|
| `nmap_scanner.py` (python-nmap `scan()`) | `engine/nmap_scanner.py` | Blocking call gave no progress and couldn't be cancelled; now subprocess + XML |
| `nmap_parser.py` | `parse_xml()` | Also keeps CPEs, OS match, NSE output, detection method |
| `nvd_client.py` | `engine/nvd_client.py` | Keyword-only, no timeout/pacing, errors returned as `[]` (FR-08/11/12, NFR-03) |
| `risk_engine.py` | `pipeline.contextual_risk` | Old version added confidence into the score; IR 2.3.4 / FR-15 keep it separate |
| `asset_context.py` | `validation.clean_context` | Stored "yes"/"no" strings where booleans were expected (bool/str bug) |
| `mitigation_engine.py` (stub) | `engine/mitigation.py` | Real Gemini call with validation and fallback (IR 2.3.5) |

Note for the report: IR Table 3 lists python-nmap. Scanning now calls the Nmap binary
directly and parses its XML with the standard library, so the GUI can show live progress
and cancel scans. Worth a sentence in the implementation chapter.

## How the GUI meets the IR requirements
| Requirement | Where |
|---|---|
| FR-01/02 target + five scan profiles | New scan page, `config.yaml` profiles |
| FR-07 version-appropriate severity bands | `pipeline.severity_from_cvss`, CVSS column shows version |
| FR-09 keyword matches flagged lower confidence | Confidence column marked `*` |
| FR-10/20, NFR-06 coverage, not-assessed services | Coverage tab + incomplete-assessment banner |
| FR-13 asset context incl. business function | New scan page |
| FR-14/15 confidence shown separately from risk | Separate Risk and Confidence columns |
| FR-16 priority bands, ordered | Table sorted by priority, then risk |
| FR-18 graphical interface | PySide6 GUI |
| FR-19 PDF and HTML export | Export buttons (ReportLab PDF, HTML, JSON) |
| NFR-04 severity, confidence, recommendation visible | All in the main table row |
| NFR-08 Windows + Linux, Nmap path per platform | `config.find_nmap`, status bar |
| NFR-10 sensitivity stated in the interface | Notice above the table, CONFIDENTIAL on reports |
| NFR-11 externally configurable | `config.yaml` |
| NFR-12 testable offline | `tests/test_core.py` |

## Security notes
- Targets are validated (`ipaddress` + strict hostname regex) and Nmap arguments only
  come from config profiles, so user input can't inject Nmap flags.
- Scans need an explicit authorisation tick each time.
- Scan output is HTML-escaped wherever it is rendered (detail panel, HTML report, PDF).
- History stays in a local SQLite file in the user's app-data folder.
