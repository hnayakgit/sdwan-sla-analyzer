#!/usr/bin/env python3
"""
Cisco SD-WAN SLA & Circuit Troubleshooting Analyzer
- Strictly On-Demand (manual run only, no scheduler/daemon)
- Strictly Single-Device per run (queries ONLY the target cEdge System IP)
- Direct to vManage REST API (no SSH to end devices)
- All timestamps & graphs in EST (America/New_York)
- Outputs: Formatted Excel Workbook (.xlsx) + Interactive HTML Dashboard (.html)
"""

import argparse
import getpass
import os
import sys
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

from vmanage_client import VManageClient
from sla_processor import analyze_sla_data
from excel_reporter import generate_excel_report
from html_reporter import generate_html_dashboard

EST_TZ = ZoneInfo("America/New_York")

DURATION_OPTIONS = {
    "1": ("Last 1 hour", 1),
    "2": ("Last 4 hours", 4),
    "3": ("Last 12 hours", 12),
    "4": ("Last 24 hours", 24),
    "5": ("Last 1 week (7 days)", 168),
}


def prompt_non_empty(label: str) -> str:
    while True:
        val = input(f"{label}: ").strip()
        if val:
            return val
        print("  Value cannot be empty. Please try again.")


def prompt_duration():
    print("\nSelect Analysis Duration:")
    for key, (label, _) in DURATION_OPTIONS.items():
        print(f"  [{key}] {label}")
    while True:
        choice = input("Enter choice [1-5]: ").strip()
        if choice in DURATION_OPTIONS:
            return DURATION_OPTIONS[choice]
        print("  Invalid selection. Please enter 1, 2, 3, 4, or 5.")


def prompt_ssl_fallback(error_msg: str) -> bool:
    print(f"\n[!] HTTPS SSL certificate verification failed ({error_msg[:120]}...)")
    ans = input("    Likely a self-signed vManage certificate. Continue without SSL verification? [y/N]: ").strip().lower()
    return ans in ("y", "yes")


def run_demo(hours: int = 4):
    from demo_data import get_demo_payloads

    print("\n[+] Running in OFFLINE DEMO mode (synthetic cEdge data — no vManage connection)...")
    (
        start_utc,
        end_utc,
        device_info,
        sla_classes,
        site_tunnels,
        events,
        approute_stats,
        policy_raw,
        app_lists,
    ) = get_demo_payloads(hours=hours)

    duration_label = f"Last {hours} hours (DEMO)"
    result = analyze_sla_data(
        vmanage_host="10.200.1.10 (DEMO)",
        device_info=device_info,
        duration_label=duration_label,
        start_utc=start_utc,
        end_utc=end_utc,
        sla_classes_raw=sla_classes,
        site_tunnels_raw=site_tunnels,
        events_raw=events,
        approute_stats_raw=approute_stats,
        policy_raw=policy_raw,
        app_lists=app_lists,
    )
    _write_outputs_and_print(result)


def _write_outputs_and_print(result):
    ts_tag = datetime.now(EST_TZ).strftime("%Y%m%d_%H%M%S_EST")
    safe_host = "".join(c if c.isalnum() or c in ("-", "_") else "_" for c in result.device_hostname)
    out_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "output", f"{safe_host}_{result.system_ip}_{ts_tag}")
    os.makedirs(out_dir, exist_ok=True)

    xlsx_path = os.path.join(out_dir, f"SLA_Report_{safe_host}_{result.system_ip}.xlsx")
    html_path = os.path.join(out_dir, f"SLA_Dashboard_{safe_host}_{result.system_ip}.html")

    generate_excel_report(result, xlsx_path)
    generate_html_dashboard(result, html_path)

    print("\n" + "=" * 70)
    print(f"  {result.verdict_title}")
    print("=" * 70)
    print(f"  Device         : {result.device_hostname} ({result.system_ip}) | Site ID: {result.site_id}")
    print(f"  Window (EST)   : {result.start_est_str} -> {result.end_est_str}")
    print(f"  SLA / BFD      : {result.total_sla_events} SLA-change events | {result.total_bfd_downs} BFD drops")
    print(f"  Worst Circuit  : {result.worst_transport} | Worst Queue: {result.worst_queue} ({result.worst_queue_mins:.1f}m)")
    print(f"  Peak Loss      : {result.peak_avg_loss:.1f}% Avg / {result.peak_max_loss:.1f}% Max ({result.peak_loss_time})")
    print(f"  Apps Impacted  : {len(result.app_failovers)} failover entries recorded")
    print("-" * 70)
    print(f"  Excel Report   : {xlsx_path}")
    print(f"  HTML Dashboard : {html_path}")
    print("=" * 70 + "\n")


def main():
    parser = argparse.ArgumentParser(description="On-Demand Cisco SD-WAN SLA & Circuit Troubleshooting Analyzer")
    parser.add_argument("--demo", action="store_true", help="Run offline with synthetic cEdge data to preview outputs")
    parser.add_argument("--demo-hours", type=int, default=4, help="Duration in hours for --demo mode (default: 4)")
    args = parser.parse_args()

    print("=" * 64)
    print("   Cisco SD-WAN SLA & Circuit Troubleshooting Analyzer (EST)")
    print("   On-Demand | Single Device | Direct vManage REST API")
    print("=" * 64)

    if args.demo:
        run_demo(hours=args.demo_hours)
        return

    vmanage_ip = prompt_non_empty("vManage IP / FQDN")
    username = prompt_non_empty("Username")
    password = getpass.getpass("Password: ")
    device_ip = prompt_non_empty("Target cEdge System IP")
    duration_label, hours = prompt_duration()

    end_utc = datetime.now(timezone.utc)
    start_utc = end_utc - timedelta(hours=hours)

    client = VManageClient(
        host=vmanage_ip,
        username=username,
        password=password,
        ssl_prompt_cb=prompt_ssl_fallback,
    )

    try:
        print(f"\n[+] Authenticating to vManage ({vmanage_ip})...")
        client.login()
        print("[+] Authentication successful.")

        print(f"[+] Validating target cEdge device ({device_ip})...")
        device_info = client.get_device_info(device_ip)
        hostname = device_info.get("host-name", device_ip)
        site_id = str(device_info.get("site-id", "N/A"))
        reachability = device_info.get("reachability", "unknown")
        print(f"[+] Device found: {hostname} | Site ID: {site_id} | Status: {reachability}")

        print(f"[+] Fetching SLA classes, tunnels, AAR policy definitions, events & approute stats ({duration_label})...")
        sla_classes = client.get_sla_classes(device_ip)
        site_tunnels = client.get_site_tunnels(site_id) if site_id != "N/A" else []
        events_raw = client.get_sla_and_bfd_events(device_ip, start_utc, end_utc)
        approute_stats = client.get_approute_stats(device_ip, start_utc, end_utc)
        policy_raw = client.get_policy_from_vsmart(device_ip)
        app_lists = client.get_app_lists()
        data_prefix_lists = client.get_data_prefix_lists()
        sla_class_lists = client.get_sla_class_lists()
        aar_policy_defs = client.get_aar_policy_definitions()

        print(f"[+] Retrieved {len(events_raw)} SLA/BFD events, {len(approute_stats)} approute samples, and {len(aar_policy_defs)} AAR policy definition(s). Processing 15-min EST buckets...")
        result = analyze_sla_data(
            vmanage_host=vmanage_ip,
            device_info=device_info,
            duration_label=duration_label,
            start_utc=start_utc,
            end_utc=end_utc,
            sla_classes_raw=sla_classes,
            site_tunnels_raw=site_tunnels,
            events_raw=events_raw,
            approute_stats_raw=approute_stats,
            policy_raw=policy_raw,
            app_lists=app_lists,
            aar_policy_defs=aar_policy_defs,
            data_prefix_lists=data_prefix_lists,
            sla_class_lists=sla_class_lists,
        )
        _write_outputs_and_print(result)

    except KeyboardInterrupt:
        print("\n[!] Cancelled by user.")
        sys.exit(130)
    except Exception as exc:
        print(f"\n[ERROR] {exc}")
        sys.exit(1)
    finally:
        client.logout()
        print("[+] Logged out of vManage cleanly.")


if __name__ == "__main__":
    main()
