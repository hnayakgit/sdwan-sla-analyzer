"""
SLA Data Processing & Troubleshooting Verdict Engine
- Converts all timestamps to EST (America/New_York)
- Computes 15-minute SLA Outage % per (Local Color, Remote Hub IP, SLA Class/Queue)
- Aggregates 15-minute Tunnel Loss %, Latency (ms), and Jitter (ms)
- Maps AAR Policy + SLA-Change events -> Applications moved, backup transport, and duration
- Generates automated Root-Cause Verdict (GREEN / AMBER / RED)
"""

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Set, Tuple
from zoneinfo import ZoneInfo

EST_TZ = ZoneInfo("America/New_York")
BUCKET_SECONDS = 900  # 15 minutes


def fmt_est(dt: datetime, include_date: bool = True) -> str:
    est_dt = dt.astimezone(EST_TZ)
    tz_label = est_dt.strftime("%Z") or "EST"
    if include_date:
        return est_dt.strftime(f"%Y-%m-%d %H:%M:%S {tz_label}")
    return est_dt.strftime("%H:%M")


def fmt_duration_hms(seconds: float) -> str:
    sec = max(0, int(round(seconds)))
    h, rem = divmod(sec, 3600)
    m, s = divmod(rem, 60)
    return f"{h:02d}:{m:02d}:{s:02d}"


def fmt_duration_short(seconds: float) -> str:
    sec = max(0, int(round(seconds)))
    m, s = divmod(sec, 60)
    h, m = divmod(m, 60)
    if h > 0:
        return f"{h}h {m:02d}m {s:02d}s"
    return f"{m}m {s:02d}s"


@dataclass
class SLAClassDef:
    name: str
    loss: float = 1.0
    latency: float = 150.0
    jitter: float = 30.0


@dataclass
class AARPolicyRule:
    sla_class: str
    app_list: str
    apps: List[str]
    dscp_values: List[str]
    ip_prefixes: List[str]
    preferred_colors: List[str]
    backup_colors: List[str]


@dataclass
class AppFailoverEntry:
    sla_class: str          # Queue name (e.g., Queue0, Queue1, Voice-SLA)
    application: str        # Resolved Application names (or traffic class if DSCP-only)
    app_list: str           # App-List / DSCP / IP match reference
    preferred_color: str
    moved_to_color: str
    start_est: str
    end_est: str
    duration_seconds: float
    duration_mins: float
    duration_hms: str
    failover_count: int


@dataclass
class RawEventRecord:
    timestamp_est: str
    timestamp_epoch: float
    event_type: str
    local_color: str
    remote_system_ip: str
    old_sla_classes: str
    new_sla_classes: str
    impact_summary: str
    severity: str  # "BREACH", "RECOVERED", "BFD_DOWN", "INFO"


@dataclass
class ObservedAppEntry:
    application: str
    family: str
    mapped_queue: str
    volume_mb: float
    packets: int
    vpn_id: str


@dataclass
class WanInterfaceSummary:
    ifname: str
    color: str
    speed_mbps: float
    peak_tx_mbps: float
    peak_rx_mbps: float
    peak_util_pct: float
    total_errors: int
    total_drops: int
    diagnosis: str
    # per 15-min bucket: {avg_tx_mbps, max_tx_mbps, avg_rx_mbps, max_rx_mbps, peak_util_pct, errors, drops}
    buckets: List[dict] = field(default_factory=list)


@dataclass
class AnalysisResult:
    device_hostname: str
    system_ip: str
    site_id: str
    device_status: str
    vmanage_host: str
    duration_label: str
    start_est_str: str
    end_est_str: str
    bucket_labels: List[str]          # ["08:00", "08:15", ...]
    bucket_datetimes: List[datetime]  # EST-aware datetimes
    sla_classes: Dict[str, SLAClassDef]
    tunnels: List[Tuple[str, str]]    # [(local_color, remote_system_ip), ...]
    colors: List[str]
    primary_hub_ip: str

    # heatmap[(local_color, remote_ip, sla_class)] = [pct_0..100 for each 15-min bucket]
    heatmap_pct: Dict[Tuple[str, str, str], List[float]]
    # total_out_mins[(local_color, remote_ip, sla_class)] = float minutes
    total_out_mins: Dict[Tuple[str, str, str], float]

    # tunnel_metrics[(local_color, remote_ip)] = list of dicts per bucket:
    # {avg_loss, max_loss, avg_latency, max_latency, avg_jitter, max_jitter}
    tunnel_metrics: Dict[Tuple[str, str], List[dict]]

    app_failovers: List[AppFailoverEntry]
    observed_dpi_apps: List[ObservedAppEntry]
    wan_interfaces: List[WanInterfaceSummary]
    raw_events: List[RawEventRecord]

    # Verdict & KPIs
    verdict_level: str     # "GREEN", "AMBER", "RED"
    verdict_title: str
    verdict_summary: str
    probable_cause: str
    total_sla_events: int
    total_bfd_downs: int
    worst_transport: str
    worst_queue: str
    worst_queue_mins: float
    peak_avg_loss: float
    peak_max_loss: float
    peak_loss_time: str
    peak_avg_latency: float
    peak_max_latency: float
    peak_avg_jitter: float
    peak_max_jitter: float
    backup_health_note: str


def _parse_event_payload(raw_event: dict) -> dict:
    """Safely extract inner event dictionary from vManage /event response."""
    ev_name = raw_event.get("eventname", "")
    ev_body = raw_event.get("event", {})
    if isinstance(ev_body, str):
        try:
            parsed = json.loads(ev_body)
            if isinstance(parsed, dict):
                return parsed.get(ev_name, parsed)
        except Exception:
            return {}
    if isinstance(ev_body, dict):
        return ev_body.get(ev_name, ev_body)
    return {}


def _split_sla_list(raw_val) -> List[str]:
    if not raw_val:
        return []
    if isinstance(raw_val, list):
        items = [str(x).strip() for x in raw_val]
    else:
        items = [x.strip() for x in str(raw_val).split(",")]
    return [x for x in items if x and x.lower() not in ("none", "__all_tunnels__")]


DSCP_LABELS = {
    "46": "DSCP 46 (EF / Voice)",
    "48": "DSCP 48 (CS6 / Network-Control)",
    "40": "DSCP 40 (CS5)",
    "34": "DSCP 34 (AF41 / Video)",
    "32": "DSCP 32 (CS4)",
    "26": "DSCP 26 (AF31 / Critical-Data)",
    "24": "DSCP 24 (CS3 / Call-Signaling)",
    "18": "DSCP 18 (AF21 / Transactional)",
    "16": "DSCP 16 (CS2)",
    "10": "DSCP 10 (AF11 / Bulk)",
    "0": "DSCP 0 (Best-Effort / Default)",
}


def _fmt_dscp(val: str) -> str:
    parts = [p.strip() for p in re.split(r"[,\s]+", str(val).strip()) if p.strip()]
    return ", ".join(DSCP_LABELS.get(p, f"DSCP {p}") for p in parts)


def _resolve_app_list(app_lists: dict, key: str) -> Tuple[str, List[str]]:
    val = app_lists.get(key)
    if isinstance(val, tuple) and len(val) == 2:
        return val[0], list(val[1])
    if isinstance(val, list):
        return key, list(val)
    return key, [key]


def _classify_dscp_traffic(dscp_nums: List[str]) -> str:
    """Short, executive-friendly traffic label for DSCP-only queues."""
    s = set(dscp_nums)
    if s & {"46", "40", "48"}:
        label = "Voice & Real-Time Video"
    elif s & {"32", "34", "36", "38", "24", "26", "18", "16"}:
        label = "Business-Critical Apps"
    elif s & {"8", "10", "12", "14"}:
        label = "Bulk / Low-Priority Data"
    elif "0" in s:
        label = "Best-Effort / Default Traffic"
    else:
        label = "DSCP-Matched Traffic"
    dscp_str = ", ".join(sorted(s, key=lambda x: int(x) if x.isdigit() else 999))
    return f"{label} (DSCP: {dscp_str})"


def parse_aar_policy(
    policy_from_vsmart: List[dict],
    app_lists: dict,
    known_colors: List[str],
    aar_policy_defs: Optional[List[dict]] = None,
    data_prefix_lists: Optional[Dict[str, Tuple[str, List[str]]]] = None,
    sla_class_lists: Optional[Dict[str, str]] = None,
) -> List[AARPolicyRule]:
    """
    Extract (SLA Class -> Applications / IP Prefixes / DSCP -> Preferred & Backup Colors)
    from vManage AAR policy definitions AND /device/policy/fromvsmart.
    """
    rules: List[AARPolicyRule] = []
    data_prefix_lists = data_prefix_lists or {}
    sla_class_lists = sla_class_lists or {}

    # Strategy 1: Structured demo/mock dict rows
    for item in policy_from_vsmart or []:
        if isinstance(item, dict) and "sla_class" in item and "preferred_colors" in item:
            app_list_name = item.get("app_list", item.get("sla_class"))
            _, resolved = _resolve_app_list(app_lists, app_list_name)
            apps = item.get("apps") or resolved
            pref = item.get("preferred_colors", [])
            backup = item.get("backup_colors") or [c for c in known_colors if c not in pref]
            rules.append(
                AARPolicyRule(
                    sla_class=item["sla_class"],
                    app_list=app_list_name,
                    apps=apps,
                    dscp_values=[],
                    ip_prefixes=[],
                    preferred_colors=pref,
                    backup_colors=backup,
                )
            )
    if rules:
        return rules

    # Strategy 2: Official vManage /template/policy/definition/approute/{id} JSON definitions
    for pol_def in aar_policy_defs or []:
        for seq in pol_def.get("sequences", []):
            sla_name = None
            pref_colors: List[str] = []
            backup_colors: List[str] = []
            for act in seq.get("actions", []):
                if act.get("type") == "slaClass":
                    params = act.get("parameter", [])
                    if isinstance(params, dict):
                        params = [params]
                    for p in params:
                        fld = p.get("field", "")
                        val = p.get("value") or p.get("ref") or ""
                        if fld == "name":
                            sla_name = sla_class_lists.get(val, val)
                        elif fld == "preferredColor":
                            pref_colors.extend(str(val).split())
                elif act.get("type") == "backupSlaPreferredColor":
                    val = act.get("parameter", "")
                    if isinstance(val, str):
                        backup_colors.extend(val.split())

            if not sla_name or sla_name == "__all_tunnels__":
                continue

            apps_found: List[str] = []
            dscp_found: List[str] = []
            ip_found: List[str] = []
            match_names: List[str] = []

            for entry in seq.get("match", {}).get("entries", []):
                fld = entry.get("field", "")
                val = entry.get("value") or entry.get("ref") or ""
                if not val:
                    continue
                if fld == "appList":
                    al_name, resolved_apps = _resolve_app_list(app_lists, val)
                    apps_found.extend(resolved_apps)
                    match_names.append(al_name)
                elif fld in ("dnsAppList", "app", "saasAppList"):
                    apps_found.append(str(val))
                    match_names.append(str(val))
                elif fld in ("sourceDataPrefixList", "destinationDataPrefixList"):
                    p_name, prefixes = data_prefix_lists.get(val, (val, [val]))
                    ip_found.extend(prefixes[:6])
                    match_names.append(p_name)
                elif fld in ("sourceIp", "destinationIp"):
                    ip_found.append(str(val))
                    match_names.append("IP-Match")
                elif fld == "dscp":
                    nums = [x.strip() for x in re.split(r"[,\s]+", str(val).strip()) if x.strip()]
                    dscp_found.extend(nums)
                    match_names.append(f"DSCP({','.join(nums)})")

            if not backup_colors:
                backup_colors = [c for c in known_colors if c not in pref_colors]

            rules.append(
                AARPolicyRule(
                    sla_class=sla_name,
                    app_list=", ".join(dict.fromkeys(match_names)) or sla_name,
                    apps=list(dict.fromkeys(apps_found)),
                    dscp_values=list(dict.fromkeys(dscp_found)),
                    ip_prefixes=list(dict.fromkeys(ip_found)),
                    preferred_colors=pref_colors,
                    backup_colors=backup_colors,
                )
            )
    if rules:
        return rules

    # Strategy 3: Parse CLI-style text inside /device/policy/fromvsmart
    raw_text_chunks = []
    for item in policy_from_vsmart or []:
        if isinstance(item, dict):
            for v in item.values():
                if isinstance(v, str) and ("app-route-policy" in v or "sla-class" in v):
                    raw_text_chunks.append(v)
        elif isinstance(item, str):
            raw_text_chunks.append(item)

    full_text = "\n".join(raw_text_chunks)
    if not full_text:
        return rules

    seq_blocks = re.split(r"\bsequence\s+\d+", full_text)
    for block in seq_blocks[1:]:
        sla_match = re.search(r"sla-class\s+([^\s\n]+)", block)
        if not sla_match:
            continue
        sla_name = sla_match.group(1).strip()
        if sla_name == "__all_tunnels__":
            continue

        apps_found = []
        dscp_found = []
        ip_found = []
        match_names = []

        app_list_match = re.search(r"app-list\s+([^\s\n]+)", block)
        src_pfx_match = re.search(r"source-data-prefix-list\s+([^\s\n]+)", block)
        dst_pfx_match = re.search(r"destination-data-prefix-list\s+([^\s\n]+)", block)
        src_ip_match = re.search(r"source-ip\s+([^\s\n]+)", block)
        dst_ip_match = re.search(r"destination-ip\s+([^\s\n]+)", block)
        dscp_match = re.search(r"dscp\s+([^\n]+)", block)
        pref_match = re.search(r"preferred-color\s+([^\n]+)", block)
        backup_match = re.search(r"backup-sla-preferred-color\s+([^\n]+)", block)

        if app_list_match:
            al_name, resolved_apps = _resolve_app_list(app_lists, app_list_match.group(1).strip())
            apps_found.extend(resolved_apps)
            match_names.append(al_name)
        if src_pfx_match:
            p_name, pfxs = data_prefix_lists.get(src_pfx_match.group(1).strip(), (src_pfx_match.group(1).strip(), []))
            ip_found.extend(pfxs[:6])
            match_names.append(p_name)
        if dst_pfx_match:
            p_name, pfxs = data_prefix_lists.get(dst_pfx_match.group(1).strip(), (dst_pfx_match.group(1).strip(), []))
            ip_found.extend(pfxs[:6])
            match_names.append(p_name)
        if src_ip_match:
            ip_found.append(src_ip_match.group(1).strip())
        if dst_ip_match:
            ip_found.append(dst_ip_match.group(1).strip())
        if dscp_match:
            nums = [x.strip() for x in re.split(r"[,\s]+", dscp_match.group(1).strip()) if x.strip()]
            dscp_found.extend(nums)
            match_names.append(f"DSCP({','.join(nums)})")

        pref_colors = pref_match.group(1).split() if pref_match else []
        backup_colors = backup_match.group(1).split() if backup_match else [
            c for c in known_colors if c not in pref_colors
        ]

        rules.append(
            AARPolicyRule(
                sla_class=sla_name,
                app_list=", ".join(dict.fromkeys(match_names)) or sla_name,
                apps=list(dict.fromkeys(apps_found)),
                dscp_values=list(dict.fromkeys(dscp_found)),
                ip_prefixes=list(dict.fromkeys(ip_found)),
                preferred_colors=pref_colors,
                backup_colors=backup_colors,
            )
        )

    return rules


def analyze_sla_data(
    vmanage_host: str,
    device_info: dict,
    duration_label: str,
    start_utc: datetime,
    end_utc: datetime,
    sla_classes_raw: List[dict],
    site_tunnels_raw: List[dict],
    events_raw: List[dict],
    approute_stats_raw: List[dict],
    policy_raw: List[dict],
    app_lists: Dict[str, List[str]],
    aar_policy_defs: Optional[List[dict]] = None,
    data_prefix_lists: Optional[Dict[str, Tuple[str, List[str]]]] = None,
    sla_class_lists: Optional[Dict[str, str]] = None,
    dpi_stats_raw: Optional[List[dict]] = None,
    wan_interfaces_raw: Optional[List[dict]] = None,
    interface_stats_raw: Optional[List[dict]] = None,
) -> AnalysisResult:
    # Align start_est down to nearest 15-min boundary for clean buckets
    start_est = start_utc.astimezone(EST_TZ)
    start_est = start_est.replace(minute=(start_est.minute // 15) * 15, second=0, microsecond=0)
    end_est = end_utc.astimezone(EST_TZ)

    total_seconds = max(BUCKET_SECONDS, int((end_est - start_est).total_seconds()))
    num_buckets = max(1, (total_seconds + BUCKET_SECONDS - 1) // BUCKET_SECONDS)
    window_start_epoch = start_est.timestamp()
    # Clamp actual analysis end to end_est so Last 1 Hour doesn't over-report as 75 mins
    window_end_epoch = end_est.timestamp()

    bucket_datetimes = [start_est + timedelta(minutes=15 * i) for i in range(num_buckets)]
    bucket_labels = [dt.strftime("%H:%M") for dt in bucket_datetimes]

    hostname = device_info.get("host-name") or device_info.get("deviceId") or "Unknown-cEdge"
    system_ip = device_info.get("system-ip") or device_info.get("deviceId") or "Unknown"
    site_id = str(device_info.get("site-id", "N/A"))
    device_status = device_info.get("reachability", "unknown")

    # 1. SLA Class Definitions
    sla_classes: Dict[str, SLAClassDef] = {}
    for item in sla_classes_raw:
        name = item.get("name", "")
        if name and name != "__all_tunnels__":
            sla_classes[name] = SLAClassDef(
                name=name,
                loss=float(item.get("loss", 1.0)),
                latency=float(item.get("latency", 150.0)),
                jitter=float(item.get("jitter", 30.0)),
            )

    # 2. Discover Tunnels & Colors from tunnelhealth + events + approute stats
    tunnel_set: Set[Tuple[str, str]] = set()
    for t in site_tunnels_raw:
        lc = t.get("local_color") or t.get("local-color")
        rip = t.get("remote_system_ip") or t.get("remote-system-ip")
        if lc and rip:
            tunnel_set.add((lc, rip))

    parsed_sla_events = []
    raw_event_records: List[RawEventRecord] = []
    bfd_down_count = 0

    for ev in events_raw:
        ev_name = ev.get("eventname", "")
        entry_ms = ev.get("entry_time") or ev.get("statcycletime") or 0
        ev_epoch = float(entry_ms) / 1000.0
        if ev_epoch < window_start_epoch or ev_epoch > window_end_epoch:
            continue

        inner = _parse_event_payload(ev)
        lc = inner.get("local-color") or inner.get("local_color") or "unknown"
        rip = inner.get("remote-system-ip") or inner.get("remote_system_ip") or "unknown"
        if lc != "unknown" and rip != "unknown":
            tunnel_set.add((lc, rip))

        ev_dt = datetime.fromtimestamp(ev_epoch, tz=timezone.utc)
        ts_est = fmt_est(ev_dt, include_date=True)

        if ev_name == "sla-change":
            old_q = _split_sla_list(inner.get("old-sla-classes"))
            new_q = _split_sla_list(inner.get("sla-classes"))
            for q in old_q + new_q:
                if q not in sla_classes:
                    sla_classes[q] = SLAClassDef(name=q)

            lost = [q for q in old_q if q not in new_q]
            gained = [q for q in new_q if q not in old_q]
            if lost and not gained:
                sev = "BREACH"
                summary = f"BREACH: {', '.join(lost)} lost on {lc} -> {rip}"
            elif gained and not lost:
                sev = "RECOVERED"
                summary = f"RECOVERED: {', '.join(gained)} restored on {lc} -> {rip}"
            elif lost and gained:
                sev = "BREACH"
                summary = f"CHANGE: Lost {', '.join(lost)} | Restored {', '.join(gained)}"
            else:
                sev = "INFO"
                summary = f"SLA update on {lc} -> {rip}"

            parsed_sla_events.append(
                {
                    "epoch": ev_epoch,
                    "color": lc,
                    "remote_ip": rip,
                    "old_q": old_q,
                    "new_q": new_q,
                }
            )
            raw_event_records.append(
                RawEventRecord(
                    timestamp_est=ts_est,
                    timestamp_epoch=ev_epoch,
                    event_type="sla-change",
                    local_color=lc,
                    remote_system_ip=rip,
                    old_sla_classes=", ".join(old_q) if old_q else "None",
                    new_sla_classes=", ".join(new_q) if new_q else "None",
                    impact_summary=summary,
                    severity=sev,
                )
            )

        elif ev_name == "bfd-state-change":
            new_state = str(inner.get("new-state") or inner.get("state") or "").lower()
            is_down = "down" in new_state
            if is_down:
                bfd_down_count += 1
            raw_event_records.append(
                RawEventRecord(
                    timestamp_est=ts_est,
                    timestamp_epoch=ev_epoch,
                    event_type="bfd-state-change",
                    local_color=lc,
                    remote_system_ip=rip,
                    old_sla_classes=str(inner.get("old-state", "-")),
                    new_sla_classes=str(inner.get("new-state", new_state or "-")),
                    impact_summary=(
                        f"BFD DOWN: Tunnel {lc} -> {rip} went down"
                        if is_down
                        else f"BFD UP: Tunnel {lc} -> {rip} restored"
                    ),
                    severity="BFD_DOWN" if is_down else "RECOVERED",
                )
            )

    # Sort events chronologically
    parsed_sla_events.sort(key=lambda x: x["epoch"])
    raw_event_records.sort(key=lambda x: x.timestamp_epoch)

    # Also discover tunnels from approute stats
    for st in approute_stats_raw:
        lc = st.get("local_color")
        rip = st.get("remote_system_ip")
        if lc and rip:
            tunnel_set.add((lc, rip))

    tunnels = sorted(tunnel_set, key=lambda x: (x[0], x[1]))
    colors = sorted({c for c, _ in tunnels})
    sla_names = list(sla_classes.keys()) if sla_classes else ["Default"]

    # 3. Compute 15-min SLA Outage % per (color, remote_ip, queue)
    # Track in-SLA seconds per bucket; out_of_sla_% = 100 * (1 - in_sla_sec / BUCKET_SECONDS)
    in_sla_secs: Dict[Tuple[str, str, str], List[float]] = {
        (c, rip, q): [0.0] * num_buckets
        for (c, rip) in tunnels
        for q in sla_names
    }
    # Also record breach intervals per (color, remote_ip, queue) for App Failover correlation
    breach_intervals: Dict[Tuple[str, str, str], List[Tuple[float, float]]] = defaultdict(list)

    events_by_tunnel: Dict[Tuple[str, str], List[dict]] = defaultdict(list)
    for ev in parsed_sla_events:
        events_by_tunnel[(ev["color"], ev["remote_ip"])].append(ev)

    def _credit_interval(key: Tuple[str, str, str], t0: float, t1: float):
        if t1 <= t0:
            return
        b0 = max(0, int((t0 - window_start_epoch) // BUCKET_SECONDS))
        b1 = min(num_buckets - 1, int((t1 - window_start_epoch) // BUCKET_SECONDS))
        for b in range(b0, b1 + 1):
            b_start = window_start_epoch + b * BUCKET_SECONDS
            b_end = b_start + BUCKET_SECONDS
            overlap = max(0.0, min(t1, b_end) - max(t0, b_start))
            in_sla_secs[key][b] += overlap

    for tunnel in tunnels:
        c, rip = tunnel
        t_events = events_by_tunnel.get(tunnel, [])
        if not t_events:
            # No SLA change events -> assume in-SLA across the full window
            for q in sla_names:
                for b in range(num_buckets):
                    in_sla_secs[(c, rip, q)][b] = float(BUCKET_SECONDS)
            continue

        # Track open breach start time per queue
        open_breach_start: Dict[str, Optional[float]] = {q: None for q in sla_names}
        prev_time = window_start_epoch

        for idx, ev in enumerate(t_events):
            ev_t = ev["epoch"]
            old_set = set(ev["old_q"])
            new_set = set(ev["new_q"])

            # Credit queues that were IN SLA during [prev_time, ev_t]
            for q in sla_names:
                if q in old_set:
                    _credit_interval((c, rip, q), prev_time, ev_t)
                else:
                    if idx == 0 and open_breach_start[q] is None:
                        open_breach_start[q] = window_start_epoch

            # Track breach start/end transitions
            for q in sla_names:
                if q in old_set and q not in new_set:
                    open_breach_start[q] = ev_t
                elif q not in old_set and q in new_set:
                    if open_breach_start[q] is not None:
                        breach_intervals[(c, rip, q)].append((open_breach_start[q], ev_t))
                        open_breach_start[q] = None

            prev_time = ev_t

        # Credit tail [prev_time, window_end_epoch] using final event's new_q
        final_set = set(t_events[-1]["new_q"])
        for q in sla_names:
            if q in final_set:
                _credit_interval((c, rip, q), prev_time, window_end_epoch)
                if open_breach_start[q] is not None:
                    breach_intervals[(c, rip, q)].append((open_breach_start[q], prev_time))
                    open_breach_start[q] = None
            else:
                start_b = open_breach_start[q] if open_breach_start[q] is not None else prev_time
                breach_intervals[(c, rip, q)].append((start_b, window_end_epoch))

    # Actual elapsed seconds in each bucket (handles partial last bucket accurately)
    bucket_durations = [
        max(1.0, min(window_start_epoch + (b + 1) * BUCKET_SECONDS, window_end_epoch) - (window_start_epoch + b * BUCKET_SECONDS))
        for b in range(num_buckets)
    ]

    heatmap_pct: Dict[Tuple[str, str, str], List[float]] = {}
    total_out_mins: Dict[Tuple[str, str, str], float] = {}
    for key, secs_list in in_sla_secs.items():
        pcts = [
            round(max(0.0, 100.0 - (s / bucket_durations[b]) * 100.0), 1)
            for b, s in enumerate(secs_list)
        ]
        out_secs_total = sum(max(0.0, bucket_durations[b] - s) for b, s in enumerate(secs_list))
        heatmap_pct[key] = pcts
        total_out_mins[key] = round(out_secs_total / 60.0, 2)

    # 4. Aggregate 15-min Tunnel Loss / Latency / Jitter from approute stats
    bucket_raw: Dict[Tuple[str, str, int], Dict[str, List[float]]] = defaultdict(
        lambda: {"loss": [], "latency": [], "jitter": []}
    )
    for st in approute_stats_raw:
        lc = st.get("local_color")
        rip = st.get("remote_system_ip")
        entry_ms = st.get("entry_time") or st.get("statcycletime") or 0
        if not lc or not rip or not entry_ms:
            continue
        ev_epoch = float(entry_ms) / 1000.0
        if ev_epoch < window_start_epoch or ev_epoch >= window_end_epoch:
            continue
        b_idx = int((ev_epoch - window_start_epoch) // BUCKET_SECONDS)
        if 0 <= b_idx < num_buckets:
            loss_val = float(st.get("loss_percentage", st.get("loss", 0.0)) or 0.0)
            lat_val = float(st.get("latency", 0.0) or 0.0)
            jit_val = float(st.get("jitter", 0.0) or 0.0)
            bucket_raw[(lc, rip, b_idx)]["loss"].append(loss_val)
            bucket_raw[(lc, rip, b_idx)]["latency"].append(lat_val)
            bucket_raw[(lc, rip, b_idx)]["jitter"].append(jit_val)

    tunnel_metrics: Dict[Tuple[str, str], List[dict]] = {}
    for tunnel in tunnels:
        c, rip = tunnel
        m_list = []
        for b in range(num_buckets):
            vals = bucket_raw.get((c, rip, b))
            if vals and vals["loss"]:
                m_list.append(
                    {
                        "avg_loss": round(sum(vals["loss"]) / len(vals["loss"]), 2),
                        "max_loss": round(max(vals["loss"]), 2),
                        "avg_latency": round(sum(vals["latency"]) / len(vals["latency"]), 1),
                        "max_latency": round(max(vals["latency"]), 1),
                        "avg_jitter": round(sum(vals["jitter"]) / len(vals["jitter"]), 1),
                        "max_jitter": round(max(vals["jitter"]), 1),
                    }
                )
            else:
                m_list.append(
                    {
                        "avg_loss": 0.0,
                        "max_loss": 0.0,
                        "avg_latency": 0.0,
                        "max_latency": 0.0,
                        "avg_jitter": 0.0,
                        "max_jitter": 0.0,
                    }
                )
        tunnel_metrics[tunnel] = m_list

    # Pick Primary Hub IP (hub with highest total outage minutes, or first hub)
    hub_outage = defaultdict(float)
    for (c, rip, q), mins in total_out_mins.items():
        hub_outage[rip] += mins
    primary_hub_ip = (
        max(hub_outage.items(), key=lambda x: x[1])[0]
        if hub_outage
        else (tunnels[0][1] if tunnels else "N/A")
    )

    # 5. Correlate AAR Policy + Breach Intervals -> Application Failover Entries
    aar_rules = parse_aar_policy(
        policy_raw,
        app_lists,
        colors,
        aar_policy_defs=aar_policy_defs,
        data_prefix_lists=data_prefix_lists,
        sla_class_lists=sla_class_lists,
    )
    rules_by_sla: Dict[str, List[AARPolicyRule]] = defaultdict(list)
    for r in aar_rules:
        rules_by_sla[r.sla_class].append(r)

    # 5a. Process Read-Only vManage DPI Observed Applications (outlook, webex, akamai, etc.)
    dscp_to_queue: Dict[str, str] = {}
    app_to_queue: Dict[str, str] = {}
    for r in aar_rules:
        for d in r.dscp_values:
            dscp_to_queue.setdefault(str(d), r.sla_class)
        for a in r.apps:
            app_to_queue.setdefault(a.lower(), r.sla_class)

    # Collect all breach time windows on primary_hub_ip so we prioritize apps active during breaches
    all_breach_windows: List[Tuple[float, float]] = []
    for (c, rip, q), ivs in breach_intervals.items():
        if rip == primary_hub_ip:
            all_breach_windows.extend(ivs)

    def _in_breach_window(ep: float) -> bool:
        if not all_breach_windows:
            return True
        return any(t0 - 300 <= ep <= t1 + 300 for t0, t1 in all_breach_windows)

    dpi_agg: Dict[str, dict] = {}
    dpi_apps_by_queue: Dict[str, List[Tuple[str, float]]] = defaultdict(list)
    for rec in dpi_stats_raw or []:
        app_name = (
            rec.get("application")
            or rec.get("app")
            or rec.get("app-name")
            or rec.get("name")
        )
        if not app_name or str(app_name).lower() in ("unknown", "none", ""):
            continue
        entry_ms = rec.get("entry_time") or rec.get("statcycletime") or 0
        ep = float(entry_ms) / 1000.0 if entry_ms else 0.0
        # Real-time /device/dpi/applications records have no entry_time (ep == 0) — always keep them!
        if ep and (ep < window_start_epoch or ep > window_end_epoch):
            continue
        if ep and not _in_breach_window(ep):
            continue

        octets = float(rec.get("octets") or rec.get("bytes") or rec.get("total-octets") or 0)
        pkts = int(rec.get("packets") or rec.get("total-packets") or 0)
        fam = str(rec.get("family") or rec.get("app-family") or "other")
        vpn = str(rec.get("vpn_id") or rec.get("vpn-id") or "-")
        dscp_val = rec.get("dscp")

        mapped_q = app_to_queue.get(str(app_name).lower(), "")
        if not mapped_q and dscp_val is not None:
            mapped_q = dscp_to_queue.get(str(dscp_val), "")

        key = str(app_name)
        if key not in dpi_agg:
            dpi_agg[key] = {"family": fam, "octets": 0.0, "packets": 0, "vpn": vpn, "queue": mapped_q}
        dpi_agg[key]["octets"] += octets
        dpi_agg[key]["packets"] += pkts
        if mapped_q and not dpi_agg[key]["queue"]:
            dpi_agg[key]["queue"] = mapped_q

    observed_dpi_apps: List[ObservedAppEntry] = []
    for app_name, info in sorted(dpi_agg.items(), key=lambda x: -x[1]["octets"])[:25]:
        vol_mb = round(info["octets"] / (1024.0 * 1024.0), 2)
        q_label = info["queue"] or "Observed via DPI"
        observed_dpi_apps.append(
            ObservedAppEntry(
                application=app_name,
                family=info["family"],
                mapped_queue=q_label,
                volume_mb=vol_mb,
                packets=info["packets"],
                vpn_id=info["vpn"],
            )
        )
        if info["queue"]:
            dpi_apps_by_queue[info["queue"]].append((app_name, vol_mb))

    app_failovers: List[AppFailoverEntry] = []
    for (c, rip, q), intervals in breach_intervals.items():
        if not intervals or rip != primary_hub_ip:
            continue
        total_sec = sum(max(0.0, t1 - t0) for t0, t1 in intervals)
        if total_sec < 1.0:
            continue

        first_start = min(t0 for t0, _ in intervals)
        last_end = max(t1 for _, t1 in intervals)
        start_str = fmt_est(datetime.fromtimestamp(first_start, tz=timezone.utc), include_date=True)
        end_str = fmt_est(datetime.fromtimestamp(last_end, tz=timezone.utc), include_date=True)

        # Always determine backup transport from actual healthy colors present on THIS device
        device_other_colors = [oc for oc in colors if oc != c]
        healthy_backups = [
            oc for oc in device_other_colors
            if total_out_mins.get((oc, rip, q), 0.0) < (total_sec / 60.0)
        ]
        moved_to = (
            ", ".join(healthy_backups)
            if healthy_backups
            else ("All Transports Breached (Fallback)" if device_other_colors else "No Backup Color")
        )

        # Aggregate & deduplicate all AAR rules matching this breached Queue (SLA Class)
        matched_rules = [
            r for r in rules_by_sla.get(q, [])
            if not r.preferred_colors or c in r.preferred_colors
        ]
        all_apps: List[str] = []
        all_dscps: List[str] = []
        all_ips: List[str] = []
        all_lists: List[str] = []

        for r in matched_rules:
            all_apps.extend(r.apps)
            all_dscps.extend(r.dscp_values)
            all_ips.extend(r.ip_prefixes)
            if r.app_list and not r.app_list.startswith("DSCP("):
                all_lists.append(r.app_list)

        # Enrich with real DPI application names mapped to this queue
        for dpi_app, _ in dpi_apps_by_queue.get(q, []):
            all_apps.append(dpi_app)

        uniq_apps = list(dict.fromkeys(all_apps))
        uniq_dscps = list(dict.fromkeys(all_dscps))
        uniq_ips = list(dict.fromkeys(all_ips))
        uniq_lists = list(dict.fromkeys(all_lists))

        # Build clean, non-duplicated Application / Traffic description for this Queue
        if uniq_apps:
            app_display = ", ".join(uniq_apps[:10]) + (f" (+{len(uniq_apps) - 10} more)" if len(uniq_apps) > 10 else "")
            if uniq_dscps:
                app_display += f" | {_classify_dscp_traffic(uniq_dscps)}"
            match_ref = ", ".join(uniq_lists[:3]) if uniq_lists else "AAR Policy + DPI"
        elif uniq_ips:
            app_display = f"IP Prefixes: {', '.join(uniq_ips[:5])}"
            match_ref = ", ".join(uniq_lists[:3]) if uniq_lists else "Data-Prefix-List"
        elif uniq_dscps:
            app_display = _classify_dscp_traffic(uniq_dscps)
            match_ref = f"DSCP Policy ({q})"
        else:
            app_display = f"All traffic in {q} (no app-list defined in AAR policy)"
            match_ref = "Queue-Level SLA"

        app_failovers.append(
            AppFailoverEntry(
                sla_class=q,
                application=app_display,
                app_list=match_ref,
                preferred_color=c,
                moved_to_color=moved_to,
                start_est=start_str,
                end_est=end_str,
                duration_seconds=total_sec,
                duration_mins=round(total_sec / 60.0, 1),
                duration_hms=fmt_duration_hms(total_sec),
                failover_count=len(intervals),
            )
        )

    app_failovers.sort(key=lambda x: (-x.duration_seconds, x.sla_class))

    # 5b. Aggregate 15-min WAN Interface Utilization, Errors & Drops (Transport vs Congestion vs Errors)
    wan_meta: Dict[str, dict] = {}
    for row in wan_interfaces_raw or []:
        ifn = str(row.get("ifname") or row.get("interface") or "").strip()
        if not ifn:
            continue
        spd_raw = row.get("speed-mbps") or row.get("bandwidth-upstream") or row.get("bandwidth-downstream") or 0
        try:
            spd_mbps = float(str(spd_raw).replace("Mbps", "").strip() or 0)
        except Exception:
            spd_mbps = 0.0
        wan_meta[ifn] = {
            "color": str(row.get("color") or row.get("tloc-color") or "VPN0-WAN"),
            "speed_mbps": spd_mbps,
        }

    # Filter interface stats to VPN 0 WAN interfaces (if known), else non-loopback/tunnel interfaces
    if_bucket_raw: Dict[Tuple[str, int], Dict[str, List[float]]] = defaultdict(
        lambda: {"tx": [], "rx": [], "err": [], "drop": []}
    )
    discovered_wan_ifs: Set[str] = set(wan_meta.keys())
    for st in interface_stats_raw or []:
        ifn = str(st.get("interface") or st.get("ifname") or "").strip()
        if not ifn:
            continue
        if wan_meta and ifn not in wan_meta:
            continue
        if not wan_meta and ifn.lower().startswith(("loopback", "system", "tunnel", "vlan")):
            continue
        discovered_wan_ifs.add(ifn)
        entry_ms = st.get("entry_time") or st.get("statcycletime") or 0
        if not entry_ms:
            continue
        ep = float(entry_ms) / 1000.0
        if ep < window_start_epoch or ep >= window_end_epoch:
            continue
        b_idx = int((ep - window_start_epoch) // BUCKET_SECONDS)
        if 0 <= b_idx < num_buckets:
            tx_mbps = float(st.get("tx_kbps", 0) or 0) / 1000.0
            rx_mbps = float(st.get("rx_kbps", 0) or 0) / 1000.0
            errs = float(st.get("rx_errors", 0) or 0) + float(st.get("tx_errors", 0) or 0)
            drops = float(st.get("rx_drops", 0) or 0) + float(st.get("tx_drops", 0) or 0)
            if_bucket_raw[(ifn, b_idx)]["tx"].append(tx_mbps)
            if_bucket_raw[(ifn, b_idx)]["rx"].append(rx_mbps)
            if_bucket_raw[(ifn, b_idx)]["err"].append(errs)
            if_bucket_raw[(ifn, b_idx)]["drop"].append(drops)

    wan_interfaces: List[WanInterfaceSummary] = []
    any_high_util = False
    any_if_errors = False
    any_if_drops = False

    for ifn in sorted(discovered_wan_ifs):
        meta = wan_meta.get(ifn, {"color": "VPN0-WAN", "speed_mbps": 0.0})
        spd = meta["speed_mbps"]
        b_list = []
        peak_tx = 0.0
        peak_rx = 0.0
        peak_util = 0.0
        tot_err = 0
        tot_drop = 0

        for b in range(num_buckets):
            vals = if_bucket_raw.get((ifn, b))
            if vals and vals["tx"]:
                avg_tx = round(sum(vals["tx"]) / len(vals["tx"]), 2)
                max_tx = round(max(vals["tx"]), 2)
                avg_rx = round(sum(vals["rx"]) / len(vals["rx"]), 2)
                max_rx = round(max(vals["rx"]), 2)
                b_err = int(round(sum(vals["err"])))
                b_drop = int(round(sum(vals["drop"])))
                util = round(max(max_tx, max_rx) / spd * 100.0, 1) if spd > 0 else 0.0
            else:
                avg_tx = max_tx = avg_rx = max_rx = util = 0.0
                b_err = b_drop = 0

            peak_tx = max(peak_tx, max_tx)
            peak_rx = max(peak_rx, max_rx)
            peak_util = max(peak_util, util)
            tot_err += b_err
            tot_drop += b_drop
            b_list.append(
                {
                    "avg_tx_mbps": avg_tx,
                    "max_tx_mbps": max_tx,
                    "avg_rx_mbps": avg_rx,
                    "max_rx_mbps": max_rx,
                    "peak_util_pct": util,
                    "errors": b_err,
                    "drops": b_drop,
                }
            )

        if peak_util >= 80.0:
            any_high_util = True
        if tot_err > 0:
            any_if_errors = True
        if tot_drop > 0:
            any_if_drops = True

        if tot_err > 0:
            diag = f"Interface Errors Detected ({tot_err} errors)"
        elif peak_util >= 80.0 or tot_drop > 0:
            diag = f"High Utilization / Congestion ({peak_util:.1f}% peak, {tot_drop} drops)"
        else:
            diag = "Clean Local Link (No Congestion / 0 Errors)"

        wan_interfaces.append(
            WanInterfaceSummary(
                ifname=ifn,
                color=meta["color"],
                speed_mbps=spd,
                peak_tx_mbps=round(peak_tx, 2),
                peak_rx_mbps=round(peak_rx, 2),
                peak_util_pct=round(peak_util, 1),
                total_errors=tot_err,
                total_drops=tot_drop,
                diagnosis=diag,
                buckets=b_list,
            )
        )

    # 6. Compute KPIs & Automated Root-Cause Verdict
    worst_key = max(total_out_mins.items(), key=lambda x: x[1]) if total_out_mins else ((("N/A", "N/A", "N/A")), 0.0)
    worst_color, worst_hub, worst_queue = worst_key[0]
    worst_queue_mins = worst_key[1]
    worst_transport = f"{worst_color} -> Hub {worst_hub}" if worst_queue_mins > 0 else "None (All Healthy)"

    peak_avg_loss = 0.0
    peak_max_loss = 0.0
    peak_loss_time = "N/A"
    peak_avg_latency = 0.0
    peak_max_latency = 0.0
    peak_avg_jitter = 0.0
    peak_max_jitter = 0.0

    for tunnel, m_list in tunnel_metrics.items():
        for b_idx, m in enumerate(m_list):
            if m["avg_loss"] > peak_avg_loss:
                peak_avg_loss = m["avg_loss"]
                peak_loss_time = f"{bucket_labels[b_idx]} EST"
            peak_max_loss = max(peak_max_loss, m["max_loss"])
            peak_avg_latency = max(peak_avg_latency, m["avg_latency"])
            peak_max_latency = max(peak_max_latency, m["max_latency"])
            peak_avg_jitter = max(peak_avg_jitter, m["avg_jitter"])
            peak_max_jitter = max(peak_max_jitter, m["max_jitter"])

    # Check if all transports breached simultaneously in any bucket
    simultaneous_all_breach = False
    if len(colors) >= 2:
        for b_idx in range(num_buckets):
            for q in sla_names:
                all_bad = all(
                    heatmap_pct.get((c, primary_hub_ip, q), [0.0] * num_buckets)[b_idx] > 0
                    for c in colors
                )
                if all_bad:
                    simultaneous_all_breach = True
                    break

    healthy_colors = [
        c for c in colors
        if all(total_out_mins.get((c, primary_hub_ip, q), 0.0) == 0.0 for q in sla_names)
    ]
    if healthy_colors:
        backup_health_note = f"{', '.join(healthy_colors)}: 100% In-SLA"
    elif colors:
        backup_health_note = "All transports experienced SLA breaches"
    else:
        backup_health_note = "No active tunnels detected"

    if worst_queue_mins == 0 and bfd_down_count == 0:
        probable_cause = "Healthy — No WAN Circuit, Utilization, or SLA Issue Detected"
    elif not wan_interfaces:
        probable_cause = "WAN SLA Breach Detected (No WAN Interface Stats Available — Check ISP/Carrier)"
    elif any_if_errors:
        probable_cause = "Local WAN Interface Errors / Physical Link Issue (Errors Incremented During Breach)"
    elif any_high_util or any_if_drops:
        probable_cause = "High WAN Utilization / Bandwidth Congestion (Peak >= 80% or Tx/Rx Drops)"
    else:
        probable_cause = "ISP / Carrier Transport Issue (Low Local WAN Utilization & 0 Interface Errors)"

    if simultaneous_all_breach or bfd_down_count > 0:
        verdict_level = "RED"
        verdict_title = "ROOT-CAUSE VERDICT: RED — CIRCUIT / SLA OUTAGE CONFIRMED"
        verdict_summary = (
            f"Critical circuit impact detected on {hostname} ({system_ip}). "
            f"Recorded {len(parsed_sla_events)} SLA-change events and {bfd_down_count} BFD tunnel drop(s). "
            f"Worst impacted circuit: {worst_transport} ({worst_queue}: {worst_queue_mins:.1f} mins out-of-SLA; "
            f"Peak Loss: {peak_avg_loss:.1f}% avg / {peak_max_loss:.1f}% max, Latency: {peak_max_latency:.0f} ms, Jitter: {peak_max_jitter:.0f} ms). "
            f"Probable Cause: {probable_cause}."
        )
    elif worst_queue_mins > 0:
        verdict_level = "AMBER"
        verdict_title = "ROOT-CAUSE VERDICT: AMBER — SINGLE-TRANSPORT DEGRADATION (TRAFFIC STEERED TO BACKUP)"
        app_names_preview = ", ".join(dict.fromkeys(a.sla_class for a in app_failovers[:6])) or worst_queue
        verdict_summary = (
            f"Primary circuit '{worst_color}' to Hub {worst_hub} breached {app_names_preview} (worst: {worst_queue} for {worst_queue_mins:.1f} mins; "
            f"Peak Loss: {peak_avg_loss:.1f}% avg / {peak_max_loss:.1f}% max at {peak_loss_time}, Latency: {peak_avg_latency:.0f} ms avg, Jitter: {peak_avg_jitter:.0f} ms avg). "
            f"Traffic was steered to backup ({backup_health_note}). Probable Cause: {probable_cause}."
        )
    else:
        verdict_level = "GREEN"
        verdict_title = "ROOT-CAUSE VERDICT: GREEN — NO CIRCUIT OR SLA BREACH DETECTED"
        verdict_summary = (
            f"All monitored transports ({', '.join(colors) or 'N/A'}) remained 100% within SLA across {duration_label} "
            f"with 0 SLA violations and 0 BFD drops (Peak Loss: {peak_avg_loss:.1f}%, Latency: {peak_avg_latency:.0f} ms, Jitter: {peak_avg_jitter:.0f} ms). "
            f"Conclusion: Any reported user/voice issue is NOT caused by SD-WAN circuit SLA — investigate LAN, firewall, or application/server side."
        )

    return AnalysisResult(
        device_hostname=hostname,
        system_ip=system_ip,
        site_id=site_id,
        device_status=device_status,
        vmanage_host=vmanage_host,
        duration_label=duration_label,
        start_est_str=fmt_est(start_est, include_date=True),
        end_est_str=fmt_est(end_est, include_date=True),
        bucket_labels=bucket_labels,
        bucket_datetimes=bucket_datetimes,
        sla_classes=sla_classes,
        tunnels=tunnels,
        colors=colors,
        primary_hub_ip=primary_hub_ip,
        heatmap_pct=heatmap_pct,
        total_out_mins=total_out_mins,
        tunnel_metrics=tunnel_metrics,
        app_failovers=app_failovers,
        observed_dpi_apps=observed_dpi_apps,
        wan_interfaces=wan_interfaces,
        raw_events=raw_event_records,
        verdict_level=verdict_level,
        verdict_title=verdict_title,
        verdict_summary=verdict_summary,
        probable_cause=probable_cause,
        total_sla_events=len(parsed_sla_events),
        total_bfd_downs=bfd_down_count,
        worst_transport=worst_transport,
        worst_queue=worst_queue if worst_queue_mins > 0 else "None",
        worst_queue_mins=worst_queue_mins,
        peak_avg_loss=peak_avg_loss,
        peak_max_loss=peak_max_loss,
        peak_loss_time=peak_loss_time,
        peak_avg_latency=peak_avg_latency,
        peak_max_latency=peak_max_latency,
        peak_avg_jitter=peak_avg_jitter,
        peak_max_jitter=peak_max_jitter,
        backup_health_note=backup_health_note,
    )
