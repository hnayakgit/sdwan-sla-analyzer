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

- **Python 3.9+** (macOS, Linux, or Windows)
- Network reachability from your workstation/jumpbox to **vManage HTTPS (443)**
- Read-only (or operator) vManage API credentials

---

## Step-by-Step Installation

### 1. Clone the Repository
```bash
git clone https://github.com/hanayak_cisco/sdwan-sla-analyzer.git
cd sdwan-sla-analyzer
```

### 2. Create a Virtual Environment & Install Dependencies
```bash
python3 -m venv venv
source venv/bin/activate        # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

*(If you use `uv`, you can also run directly with `uv run --with-requirements requirements.txt python3 sla_analyzer.py`.)*

---

## Step-by-Step Usage Guide for Engineers

### 1. Run the Script (On-Demand)
```bash
python3 sla_analyzer.py
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

> **Self-Signed Certificate Prompt:** If your vManage uses an internal/self-signed HTTPS certificate, the script will pause and ask: `Continue without SSL verification? [y/N]`. Type `y` to proceed.

### 3. Review the Generated Reports
Reports are automatically saved in a timestamped folder under `output/`:
```text
output/<hostname>_<system-ip>_<YYYYMMDD_HHMMSS_EST>/
├── SLA_Report_<hostname>_<system-ip>.xlsx      # Customer-ready 5-tab Excel workbook
└── SLA_Dashboard_<hostname>_<system-ip>.html   # Interactive browser dashboard
```

---

## Understanding the Output Tabs

| Tab / Section | Purpose |
| :--- | :--- |
| **1. Executive Summary** | Plain-English Root-Cause Verdict (Green/Amber/Red), Device Metadata, Key KPIs, and an **SLA Outage Timeline (EST)** showing exactly when the outage started and recovered. |
| **2. 15min SLA Heatmap** | Color-coded Green → Yellow → Red grid showing `% of Time Out-of-SLA` for every `(Local Color, Remote Hub IP, SLA Class/Queue)` across every 15-minute bucket. |
| **3. 15min Tunnel Metrics** | Actual 15-minute Avg/Max **Packet Loss %**, **Latency (ms)**, and **Jitter (ms)** from vManage `approute` stats with red SLA breach highlighting and Latency/Jitter trend charts. |
| **4. App Failover Summary** | Correlates the device's AAR policy with `sla-change` events to list which **Applications / App-Lists** moved from primary to backup transport, exact EST start/end times, and total duration. |
| **5. Raw SLA & BFD Events** | Filterable chronological audit log of every `sla-change` and `bfd-state-change` event in EST. |

---

## Offline Demo Mode (Test Without vManage)
Engineers can test the tool and preview the Excel + HTML outputs anytime without connecting to a live vManage:
```bash
python3 sla_analyzer.py --demo
```

---

## Security & Best Practices
- Credentials are **never stored** on disk or logged.
- The `.gitignore` file excludes `output/`, `*.xlsx`, and `*.html` so customer telemetry is never accidentally committed to Git.
- The tool always calls `/logout` on vManage when finished (even if interrupted with `Ctrl+C`).
