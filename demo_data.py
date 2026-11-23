"""
Synthetic Demo Data Generator (used ONLY when running with --demo flag for offline verification)
"""

import json
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

EST_TZ = ZoneInfo("America/New_York")


def get_demo_payloads(hours: int = 4):
    now_est = datetime.now(EST_TZ).replace(minute=(datetime.now(EST_TZ).minute // 15) * 15, second=0, microsecond=0)
    start_est = now_est - timedelta(hours=hours)
    start_utc = start_est.astimezone(timezone.utc)
    end_utc = now_est.astimezone(timezone.utc)

    # Place a realistic 28-minute MPLS SLA degradation window roughly 60% into the selected range
    incident_start = start_est + timedelta(minutes=int(hours * 60 * 0.55))
    incident_start = incident_start.replace(second=15)

    device_info = {
        "host-name": "BRANCH-NYC-01",
        "system-ip": "10.50.12.1",
        "deviceId": "10.50.12.1",
        "site-id": "5012",
        "reachability": "reachable",
    }

    sla_classes = [
        {"name": "Voice-SLA", "loss": 1.0, "latency": 50.0, "jitter": 10.0},
        {"name": "Biz-Critical", "loss": 2.0, "latency": 120.0, "jitter": 25.0},
        {"name": "Default", "loss": 5.0, "latency": 250.0, "jitter": 50.0},
    ]

    site_tunnels = [
        {"local_color": "mpls", "remote_system_ip": "10.1.0.1"},
        {"local_color": "mpls", "remote_system_ip": "10.1.0.2"},
        {"local_color": "biz-internet", "remote_system_ip": "10.1.0.1"},
        {"local_color": "biz-internet", "remote_system_ip": "10.1.0.2"},
    ]

    def _mk_sla_event(dt_est: datetime, color: str, rip: str, old_q: str, new_q: str):
        ms = int(dt_est.astimezone(timezone.utc).timestamp() * 1000)
        return {
            "eventname": "sla-change",
            "entry_time": ms,
            "event": json.dumps(
                {
                    "sla-change": {
                        "local-color": color,
                        "remote-system-ip": rip,
                        "old-sla-classes": old_q,
                        "sla-classes": new_q,
                    }
                }
            ),
        }

    events = [
        _mk_sla_event(incident_start, "mpls", "10.1.0.1", "Voice-SLA, Biz-Critical, Default", "Biz-Critical, Default"),
        _mk_sla_event(incident_start + timedelta(minutes=4, seconds=15), "mpls", "10.1.0.2", "Voice-SLA, Biz-Critical, Default", "Biz-Critical, Default"),
        _mk_sla_event(incident_start + timedelta(minutes=6, seconds=45), "mpls", "10.1.0.1", "Biz-Critical, Default", "Default"),
        _mk_sla_event(incident_start + timedelta(minutes=16, seconds=15), "mpls", "10.1.0.2", "Biz-Critical, Default", "Voice-SLA, Biz-Critical, Default"),
        _mk_sla_event(incident_start + timedelta(minutes=24), "mpls", "10.1.0.1", "Default", "Biz-Critical, Default"),
        _mk_sla_event(incident_start + timedelta(minutes=27, seconds=45), "mpls", "10.1.0.1", "Biz-Critical, Default", "Voice-SLA, Biz-Critical, Default"),
    ]

    # Generate 5-min approute stats across the entire duration
    approute_stats = []
    cursor = start_est
    incident_end = incident_start + timedelta(minutes=28)
    while cursor < now_est:
        ms = int(cursor.astimezone(timezone.utc).timestamp() * 1000)
        in_incident = incident_start <= cursor <= incident_end
        for color, rip in [("mpls", "10.1.0.1"), ("mpls", "10.1.0.2"), ("biz-internet", "10.1.0.1"), ("biz-internet", "10.1.0.2")]:
            if color == "mpls" and in_incident:
                loss = 3.2 if rip == "10.1.0.1" else 1.8
                lat = 66.0 if rip == "10.1.0.1" else 48.0
                jit = 19.0 if rip == "10.1.0.1" else 13.0
            elif color == "mpls":
                loss, lat, jit = 0.05, 18.5, 2.0
            else:
                loss, lat, jit = 0.05, 26.0, 3.0
            approute_stats.append(
                {
                    "entry_time": ms,
                    "local_color": color,
                    "remote_system_ip": rip,
                    "loss_percentage": loss,
                    "latency": lat,
                    "jitter": jit,
                }
            )
        cursor += timedelta(minutes=5)

    policy_raw = [
        {
            "sla_class": "Voice-SLA",
            "app_list": "Voice-Apps",
            "apps": ["Webex", "Cisco-Jabber", "MS-Teams"],
            "preferred_colors": ["mpls"],
            "backup_colors": ["biz-internet"],
        },
        {
            "sla_class": "Biz-Critical",
            "app_list": "Biz-Apps",
            "apps": ["SAP", "Salesforce"],
            "preferred_colors": ["mpls"],
            "backup_colors": ["biz-internet"],
        },
    ]

    app_lists = {
        "Voice-Apps": ["Webex", "Cisco-Jabber", "MS-Teams"],
        "Biz-Apps": ["SAP", "Salesforce"],
    }

    return (
        start_utc,
        end_utc,
        device_info,
        sla_classes,
        site_tunnels,
        events,
        approute_stats,
        policy_raw,
        app_lists,
    )
