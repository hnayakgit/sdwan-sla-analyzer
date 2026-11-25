# Cisco SD-WAN SLA & Circuit Troubleshooting Analyzer

An on-demand, single-device Python tool for **Cisco Catalyst SD-WAN (vManage)** designed for large Hub-and-Spoke environments (2,000+ branches across multiple independent overlays).

Instead of digging through thousands of raw `sla-change` events in vManage, engineers run this script on demand for a **single cEdge System IP** and immediately get:
1. A **customer-ready Excel Workbook (`.xlsx`)** with an Executive Summary, Root-Cause Verdict, 15-minute SLA Violation Heatmap per Queue, 15-minute Tunnel Performance Metrics, Application Failover Summary, and Raw Event Audit Log.
2. A **standalone Interactive HTML Dashboard (`.html`)** with zoomable Plotly charts that can be opened in any browser or shared directly with customers.

---

## Key Features

- **Direct to vManage REST API Only:** Never SSHs to WAN Edge routers.
- **Strictly Single-Device & On-Demand:** Queries *only* the single cEdge System IP entered at the prompt (never pulls fabric-wide data for all 2,000+ branches). No background service or auto-run.
- **Multi-Overlay Ready:** Prompts for vManage IP and credentials every run so engineers can target any independent overlay controller.
- **Smart SSL Handling:** Attempts verified HTTPS first and prompts cleanly before falling back if a controller uses a self-signed certificate.
- **EST Timezone (`America/New_York`):** All timestamps, 15-minute buckets, tables, and chart baselines are standardized to EST.
- **Automated Root-Cause Verdict:**
  - **GREEN:** No SLA/circuit breach detected (points engineers to LAN, firewall, or application/server side).
  - **AMBER:** Single-transport degradation — primary circuit breached SLA and apps automatically moved to backup transport.
  - **RED:** Critical circuit/SLA outage — all transports breached simultaneously or BFD tunnel drops occurred.

---

## Prerequisites

- **Python 3.9 or newer**
- Network reachability from your workstation/jumpbox to **vManage HTTPS (443)**
- Read-only vManage API credentials (recommended)
- Terminal access: Terminal on macOS, PowerShell or Command Prompt on Windows

This tool is **read-only for vManage and the end device**. It retrieves monitoring data and writes reports locally. It does not configure, deploy, reboot, commit, or run CLI commands on a device.

Repository links:

- Public: https://github.com/hnayakgit/sdwan-sla-analyzer
- Private: https://github.com/hanayak_cisco/sdwan-sla-analyzer

---

## Step-by-Step Installation

### 1. Clone the Repository
```bash
git clone https://github.com/hnayakgit/sdwan-sla-analyzer.git
cd sdwan-sla-analyzer
```

Use the private repository URL instead if your organization requires it:

```bash
git clone https://github.com/hanayak_cisco/sdwan-sla-analyzer.git
cd sdwan-sla-analyzer
```

### 2. Create a Virtual Environment & Install Dependencies

**macOS:**
```bash
python3 -m venv venv
source venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

**Windows (PowerShell):**
```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

If PowerShell blocks activation, run PowerShell as your normal user and execute this once:

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

Then activate the environment again.

**Windows (Command Prompt / `cmd`):**
```cmd
python -m venv venv
venv\Scripts\activate.bat
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

After activation, your prompt normally shows `(venv)`.

---

## Step-by-Step Usage Guide for Engineers

### 1. Run the Script (On-Demand)

**macOS:**
```bash
python3 sla_analyzer.py
```

**Windows PowerShell:**
```powershell
python sla_analyzer.py
```

**Windows Command Prompt:**
```cmd
python sla_analyzer.py
```

If the `python` command is not found on Windows, try `py` instead:

```powershell
py sla_analyzer.py
```

### 2. Enter the Interactive Prompts
The script will ask for:
1. **vManage IP / FQDN** — Enter the vManage controller IP for the overlay managing the target branch.
2. **Username & Password** — Your vManage login (password input is hidden; nothing is saved to disk).
3. **Target cEdge System IP** — Exact System IP of the single branch router you are troubleshooting (e.g., `10.50.12.1`).
4. **Analysis Duration:**
   - `[1]` Last 1 hour
   - `[2]` Last 4 hours
   - `[3]` Last 12 hours
   - `[4]` Last 24 hours
   - `[5]` Last 1 week (7 days)

Recommended checks:

- Use **`[2] Last 4 hours`** for a quick validation run.
- Use **`[5] Last 1 week (7 days)`** for the full production report.
- Enter the exact cEdge **System IP**, not a WAN interface IP or hostname.

> **Self-Signed Certificate Prompt:** If your vManage uses an internal/self-signed HTTPS certificate, the script will pause and ask: `Continue without SSL verification? [y/N]`. Type `y` to proceed.

### 3. Review the Generated Reports
Reports are automatically saved in a timestamped folder under `output/`:
```text
output/<hostname>_<system-ip>_<YYYYMMDD_HHMMSS_EST>/
├── SLA_Report_<hostname>_<system-ip>.xlsx      # Customer-ready Excel workbook
└── SLA_Dashboard_<hostname>_<system-ip>.html   # Interactive browser dashboard
```

Open the `.xlsx` file in Microsoft Excel or LibreOffice. Open the `.html` file in a browser.

---

## Understanding the Output Tabs

The Excel workbook contains **seven tabs**. The first tab is the quick executive view; the remaining tabs provide supporting detail.

| Tab / Section | Purpose |
| :--- | :--- |
| **1. Executive Summary** | Plain-English Root-Cause Verdict (Green/Amber/Red), Device Metadata, Key KPIs, and an **SLA Outage Timeline (EST)** showing exactly when the outage started and recovered. |
| **2. 15min SLA Heatmap** | Color-coded Green → Yellow → Red grid showing `% of Time Out-of-SLA` for every `(Local Color, Remote Hub IP, SLA Class/Queue)` across every 15-minute bucket. |
| **3. 15min Tunnel Metrics** | Actual 15-minute Avg/Max **Packet Loss %**, **Latency (ms)**, and **Jitter (ms)** from vManage `approute` stats with red SLA breach highlighting and Latency/Jitter trend charts. |
| **4. App Failover Summary** | Correlates the device's AAR policy with `sla-change` events to list which **Applications / App-Lists** moved from primary to backup transport, exact EST start/end times, and total duration. |
| **5. Raw SLA & BFD Events** | Filterable chronological audit log of every `sla-change` and `bfd-state-change` event in EST. |
| **6. WAN Utilization & Errors** | 15-minute VPN 0 WAN interface Tx/Rx Mbps, link utilization %, interface errors & drops, and automated diagnosis distinguishing **ISP/Carrier Transport Issue** vs. **High Utilization/Congestion** vs. **Local Link Errors**. |
| **7. TLOC & Subinterface Performance** | Active-color subinterface utilization, TLOC loss by local color and remote hub, loss thresholds, and items without a reliable subinterface mapping. |

---

## Offline Demo Mode (Test Without vManage)
Engineers can test the tool and preview the Excel + HTML outputs anytime without connecting to a live vManage:
**macOS / Linux:**
```bash
python3 sla_analyzer.py --demo
```

**Windows:**
```powershell
python sla_analyzer.py --demo
```

Demo mode does not contact vManage. It creates sample Excel and HTML reports so you can verify the installation first.

## Troubleshooting

### `python` or `python3` is not found

Install Python 3.9+ from https://www.python.org/downloads/ and enable the option to add Python to `PATH` on Windows. Close and reopen the terminal after installation.

### `No module named ...`

Activate the virtual environment and reinstall dependencies:

**macOS:**
```bash
source venv/bin/activate
python -m pip install -r requirements.txt
```

**Windows PowerShell:**
```powershell
.\venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

### SSL certificate warning

The script tries verified HTTPS first. If your controller uses an internal or self-signed certificate, it will ask whether to continue without certificate verification. Confirm this only when you recognize the vManage controller.

### No data or device not found

Verify the vManage address, credentials, controller overlay, target cEdge System IP, and HTTPS reachability on port 443. The account must be able to read device monitoring and policy data.

---

## Read-Only Safety and Best Practices
- Credentials are **never stored** on disk or logged.
- The `.gitignore` file excludes `output/`, `*.xlsx`, and `*.html` so customer telemetry is never accidentally committed to Git.
- The tool always calls `/logout` on vManage when finished (even if interrupted with `Ctrl+C`).
- Use a read-only vManage account whenever possible.
- Treat generated Excel and HTML files as customer data and share them only through approved channels.
