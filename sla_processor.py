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
    preferred_colors: List[str]
    backup_colors: List[str]


@dataclass
class AppFailoverEntry:
    application: str
    app_list: str
    sla_class: str
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
    raw_events: List[RawEventRecord]

    # Verdict & KPIs
    verdict_level: str     # "GREEN", "AMBER", "RED"
    verdict_title: str
    verdict_summary: str
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


def parse_aar_policy(
    policy_from_vsmart: List[dict],
    app_lists: Dict[str, List[str]],
    known_colors: List[str],
) -> List[AARPolicyRule]:
    """
    Extract (SLA Class -> App-List / Applications -> Preferred & Backup Colors)
    from vManage /device/policy/fromvsmart output.
    """
    rules: List[AARPolicyRule] = []
    if not policy_from_vsmart:
        return rules

    # Strategy 1: Structured dict rows (common on some vManage / mock payloads)
    for item in policy_from_vsmart:
        if isinstance(item, dict) and "sla_class" in item and "preferred_colors" in item:
            app_list_name = item.get("app_list", item.get("sla_class"))
            apps = item.get("apps") or app_lists.get(app_list_name, [app_list_name])
            pref = item.get("preferred_colors", [])
            backup = item.get("backup_colors") or [c for c in known_colors if c not in pref]
            rules.append(
                AARPolicyRule(
                    sla_class=item["sla_class"],
                    app_list=app_list_name,
                    apps=apps,
                    preferred_colors=pref,
                    backup_colors=backup,
                )
            )
    if rules:
        return rules

    # Strategy 2: Parse CLI-style text inside 'policy' or 'definition' fields from /device/policy/fromvsmart
    raw_text_chunks = []
    for item in policy_from_vsmart:
        if isinstance(item, dict):
            for v in item.values():
                if isinstance(v, str) and ("app-route-policy" in v or "sla-class" in v):
                    raw_text_chunks.append(v)
        elif isinstance(item, str):
            raw_text_chunks.append(item)

    full_text = "\n".join(raw_text_chunks)
    if not full_text:
        return rules

    # Parse sequence blocks inside app-route-policy
    seq_blocks = re.split(r"\bsequence\s+\d+", full_text)
    for block in seq_blocks[1:]:
        sla_match = re.search(r"sla-class\s+([^\s\n]+)", block)
        if not sla_match:
            continue
        sla_name = sla_match.group(1).strip()
        if sla_name == "__all_tunnels__":
            continue

        app_list_match = re.search(r"app-list\s+([^\s\n]+)", block)
        dscp_match = re.search(r"dscp\s+([^\n]+)", block)
        pref_match = re.search(r"preferred-color\s+([^\n]+)", block)
        backup_match = re.search(r"backup-sla-preferred-color\s+([^\n]+)", block)

        app_list_name = app_list_match.group(1).strip() if app_list_match else (
            f"DSCP {dscp_match.group(1).strip()}" if dscp_match else sla_name
        )
        apps = app_lists.get(app_list_name, [app_list_name])
        pref_colors = pref_match.group(1).split() if pref_match else []
        backup_colors = backup_match.group(1).split() if backup_match else [
            c for c in known_colors if c not in pref_colors
        ]

        rules.append(
            AARPolicyRule(
                sla_class=sla_name,
                app_list=app_list_name,
                apps=apps,
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
) -> AnalysisResult:
    # Align start_est down to nearest 15-min boundary for clean buckets
    start_est = start_utc.astimezone(EST_TZ)
    start_est = start_est.replace(minute=(start_est.minute // 15) * 15, second=0, microsecond=0)
    end_est = end_utc.astimezone(EST_TZ)

    total_seconds = max(BUCKET_SECONDS, int((end_est - start_est).total_seconds()))
    num_buckets = max(1, (total_seconds + BUCKET_SECONDS - 1) // BUCKET_SECONDS)
    # Cap window end cleanly to num_buckets * 15 mins
    window_start_epoch = start_est.timestamp()
    window_end_epoch = window_start_epoch + num_buckets * BUCKET_SECONDS

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

    heatmap_pct: Dict[Tuple[str, str, str], List[float]] = {}
    total_out_mins: Dict[Tuple[str, str, str], float] = {}
    for key, secs_list in in_sla_secs.items():
        pcts = [round(max(0.0, 100.0 - (s / BUCKET_SECONDS) * 100.0), 1) for s in secs_list]
        heatmap_pct[key] = pcts
        total_out_mins[key] = round(sum(pcts) / 100.0 * 15.0, 2)

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
    aar_rules = parse_aar_policy(policy_raw, app_lists, colors)
    rules_by_sla: Dict[str, List[AARPolicyRule]] = defaultdict(list)
    for r in aar_rules:
        rules_by_sla[r.sla_class].append(r)

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

        matched_rules = rules_by_sla.get(q, [])
        if matched_rules:
            for rule in matched_rules:
                if rule.preferred_colors and c not in rule.preferred_colors:
                    continue
                # Determine backup color(s) that remained healthy
                healthy_backups = [
                    bc for bc in rule.backup_colors
                    if total_out_mins.get((bc, rip, q), 0.0) < (total_sec / 60.0)
                ]
                moved_to = ", ".join(healthy_backups) if healthy_backups else "All Transports Breached (Fallback)"
                for app_name in rule.apps:
                    app_failovers.append(
                        AppFailoverEntry(
                            application=app_name,
                            app_list=rule.app_list,
                            sla_class=q,
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
        else:
            # Fallback if AAR policy didn't expose app names
            other_colors = [oc for oc in colors if oc != c]
            moved_to = ", ".join(other_colors) if other_colors else "No Backup Color"
            app_failovers.append(
                AppFailoverEntry(
                    application=f"{q} Traffic",
                    app_list="Policy-Mapped",
                    sla_class=q,
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

    app_failovers.sort(key=lambda x: (-x.duration_seconds, x.application))

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

    if simultaneous_all_breach or bfd_down_count > 0:
        verdict_level = "RED"
        verdict_title = "ROOT-CAUSE VERDICT: RED — CIRCUIT / SLA OUTAGE CONFIRMED"
        verdict_summary = (
            f"Critical circuit impact detected on {hostname} ({system_ip}). "
            f"Recorded {len(parsed_sla_events)} SLA-change events and {bfd_down_count} BFD tunnel drop(s). "
            f"Worst impacted circuit: {worst_transport} ({worst_queue}: {worst_queue_mins:.1f} mins out-of-SLA; "
            f"Peak Loss: {peak_avg_loss:.1f}% avg / {peak_max_loss:.1f}% max, Latency: {peak_max_latency:.0f} ms, Jitter: {peak_max_jitter:.0f} ms). "
            f"Conclusion: Site/application issues during this window WERE caused by WAN circuit/SLA degradation."
        )
    elif worst_queue_mins > 0:
        verdict_level = "AMBER"
        verdict_title = "ROOT-CAUSE VERDICT: AMBER — SINGLE-TRANSPORT DEGRADATION (TRAFFIC STEERED TO BACKUP)"
        app_names_preview = ", ".join(dict.fromkeys(a.application for a in app_failovers[:6])) or worst_queue
        verdict_summary = (
            f"Primary circuit '{worst_color}' to Hub {worst_hub} breached {worst_queue} for {worst_queue_mins:.1f} mins "
            f"(Peak Loss: {peak_avg_loss:.1f}% avg / {peak_max_loss:.1f}% max at {peak_loss_time}, Latency: {peak_avg_latency:.0f} ms avg, Jitter: {peak_avg_jitter:.0f} ms avg). "
            f"Affected traffic ({app_names_preview}) was automatically steered to backup transport ({backup_health_note}). "
            f"Conclusion: Any voice/app blip during this window aligns with primary circuit SLA degradation & failover."
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
        raw_events=raw_event_records,
        verdict_level=verdict_level,
        verdict_title=verdict_title,
        verdict_summary=verdict_summary,
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
