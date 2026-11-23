"""
Interactive Standalone HTML Dashboard Generator (EST Timezone)
- Opens in any browser (zero setup) — easy to share with customers & engineers
- Interactive Plotly charts: 15-min SLA Heatmap, Tunnel Loss/Latency/Jitter Timelines, App Failover Bar Chart
- Color-coded Root-Cause Verdict banner + KPI cards + Event Audit Table
"""

import html
import plotly.graph_objects as go
from plotly.subplots import make_subplots

from sla_processor import AnalysisResult


def _esc(val) -> str:
    return html.escape(str(val))


def generate_html_dashboard(result: AnalysisResult, output_path: str) -> str:
    sla_names = list(result.sla_classes.keys()) if result.sla_classes else ["Default"]
    primary_color = result.colors[0] if result.colors else "mpls"
    if result.worst_transport != "None (All Healthy)" and " -> " in result.worst_transport:
        primary_color = result.worst_transport.split(" -> ")[0].strip()

    # 1. Interactive 15-Min SLA Outage Heatmap
    y_labels = []
    z_matrix = []
    for color, rip in result.tunnels:
        for q in sla_names:
            y_labels.append(f"{color} → {rip} | {q}")
            z_matrix.append(result.heatmap_pct.get((color, rip, q), [0.0] * len(result.bucket_labels)))

    fig_hm = go.Figure(
        data=go.Heatmap(
            z=z_matrix,
            x=result.bucket_labels,
            y=y_labels,
            colorscale=[[0.0, "#DFF6DD"], [0.45, "#FFE699"], [1.0, "#F8696B"]],
            zmin=0,
            zmax=100,
            colorbar=dict(title="% Out of SLA"),
            hovertemplate="<b>%{y}</b><br>Time (EST): %{x}<br>Out of SLA: <b>%{z:.1f}%</b><extra></extra>",
        )
    )
    fig_hm.update_layout(
        title="15-Minute SLA Violation Heatmap (% Time Out-of-SLA per Queue — EST)",
        xaxis_title="Time (EST)",
        height=max(320, 140 + 28 * len(y_labels)),
        margin=dict(l=230, r=30, t=55, b=55),
        template="plotly_white",
    )
    hm_html = fig_hm.to_html(full_html=False, include_plotlyjs="cdn")

    # 2. Interactive Tunnel Loss %, Latency (ms), Jitter (ms) Subplots (Hover for exact values!)
    fig_metrics = make_subplots(
        rows=3,
        cols=1,
        shared_xaxes=True,
        vertical_spacing=0.08,
        subplot_titles=(
            f"Average Packet Loss (%) — Hub {result.primary_hub_ip}",
            f"Average Latency (ms) — Hub {result.primary_hub_ip}",
            f"Average Jitter (ms) — Hub {result.primary_hub_ip}",
        ),
    )

    color_palette = ["#D93025", "#005073", "#007A87", "#7B1FA2", "#E67C00"]
    for idx, color in enumerate(result.colors):
        m_list = result.tunnel_metrics.get((color, result.primary_hub_ip), [])
        if not m_list:
            continue
        hex_c = color_palette[idx % len(color_palette)]
        losses = [m["avg_loss"] for m in m_list]
        lats = [m["avg_latency"] for m in m_list]
        jits = [m["avg_jitter"] for m in m_list]

        fig_metrics.add_trace(
            go.Scatter(x=result.bucket_labels, y=losses, mode="lines+markers", name=f"{color}", line=dict(color=hex_c, width=2.5), legendgroup=color),
            row=1, col=1,
        )
        fig_metrics.add_trace(
            go.Scatter(x=result.bucket_labels, y=lats, mode="lines+markers", name=f"{color}", line=dict(color=hex_c, width=2.5), legendgroup=color, showlegend=False),
            row=2, col=1,
        )
        fig_metrics.add_trace(
            go.Scatter(x=result.bucket_labels, y=jits, mode="lines+markers", name=f"{color}", line=dict(color=hex_c, width=2.5), legendgroup=color, showlegend=False),
            row=3, col=1,
        )

    strict_sla = min(result.sla_classes.values(), key=lambda x: x.loss) if result.sla_classes else None
    if strict_sla:
        fig_metrics.add_hline(y=strict_sla.loss, line_dash="dash", line_color="#E67C00", annotation_text=f"{strict_sla.name} Loss Limit ({strict_sla.loss}%)", row=1, col=1)
        fig_metrics.add_hline(y=strict_sla.latency, line_dash="dash", line_color="#E67C00", annotation_text=f"{strict_sla.name} Latency Limit ({strict_sla.latency} ms)", row=2, col=1)
        fig_metrics.add_hline(y=strict_sla.jitter, line_dash="dash", line_color="#E67C00", annotation_text=f"{strict_sla.name} Jitter Limit ({strict_sla.jitter} ms)", row=3, col=1)

    fig_metrics.update_xaxes(title_text="Time (EST)", row=3, col=1)
    fig_metrics.update_yaxes(title_text="Loss (%)", row=1, col=1)
    fig_metrics.update_yaxes(title_text="Latency (ms)", row=2, col=1)
    fig_metrics.update_yaxes(title_text="Jitter (ms)", row=3, col=1)
    fig_metrics.update_layout(
        height=760,
        hovermode="x unified",
        legend=dict(orientation="h", yanchor="bottom", y=1.04, xanchor="left", x=0),
        margin=dict(l=65, r=30, t=70, b=55),
        template="plotly_white",
    )
    metrics_html = fig_metrics.to_html(full_html=False, include_plotlyjs=False)

    # 3. Interactive App Failover Chart (by Breached Queue)
    if result.app_failovers:
        fig_app = go.Figure(
            data=go.Bar(
                x=[a.sla_class for a in result.app_failovers],
                y=[a.duration_mins for a in result.app_failovers],
                customdata=[a.application for a in result.app_failovers],
                marker_color="#005073",
                hovertemplate="<b>%{x}</b><br>Applications: %{customdata}<br>Duration on Backup: <b>%{y:.1f} mins</b><extra></extra>",
            )
        )
        fig_app.update_layout(
            title="Failover Duration on Backup Transport by Breached Queue (Minutes)",
            yaxis_title="Duration (Minutes)",
            height=340,
            margin=dict(l=65, r=30, t=55, b=55),
            template="plotly_white",
        )
        app_chart_html = fig_app.to_html(full_html=False, include_plotlyjs=False)
    else:
        app_chart_html = '<div class="empty-ok">Zero application failover events occurred during this EST window.</div>'

    # App Failover Table Rows (Queue + Affected Applications side-by-side)
    if result.app_failovers:
        app_rows_html = "".join(
            f"<tr><td><b>{_esc(a.sla_class)}</b></td><td><b>{_esc(a.application)}</b></td><td>{_esc(a.app_list)}</td>"
            f"<td>{_esc(a.preferred_color)}</td><td><b>{_esc(a.moved_to_color)}</b></td>"
            f"<td>{_esc(a.start_est)}</td><td>{_esc(a.end_est)}</td>"
            f"<td><b>{a.duration_mins:.1f} m</b> ({_esc(a.duration_hms)})</td><td>{a.failover_count}</td></tr>"
            for a in result.app_failovers
        )
    else:
        app_rows_html = '<tr><td colspan="9" style="text-align:center;color:#107C10;font-weight:600;">No application failovers detected.</td></tr>'

    # DPI Observed Applications Table Rows
    if result.observed_dpi_apps:
        dpi_rows_html = "".join(
            f"<tr><td><b>{_esc(d.application)}</b></td><td>{_esc(d.family)}</td><td>{_esc(d.mapped_queue)}</td>"
            f"<td>{d.volume_mb:.2f} MB</td><td>{d.packets:,}</td><td>{_esc(d.vpn_id)}</td></tr>"
            for d in result.observed_dpi_apps
        )
    else:
        dpi_rows_html = '<tr><td colspan="6" style="text-align:center;color:#57606A;">vManage DPI returned 0 application records for this device/window.</td></tr>'

    # 4. Interactive WAN Interface Utilization & Errors Chart + Table
    if result.wan_interfaces:
        fig_wan = go.Figure()
        wan_palette = ["#D93025", "#E67C00", "#005073", "#007A87", "#7B1FA2", "#2E7D32"]
        c_idx = 0
        for w_if in result.wan_interfaces[:3]:
            tx_vals = [b["max_tx_mbps"] for b in w_if.buckets]
            rx_vals = [b["max_rx_mbps"] for b in w_if.buckets]
            fig_wan.add_trace(
                go.Scatter(x=result.bucket_labels, y=tx_vals, mode="lines+markers", name=f"{w_if.ifname} Tx (Mbps)", line=dict(color=wan_palette[c_idx % len(wan_palette)], width=2.2))
            )
            c_idx += 1
            fig_wan.add_trace(
                go.Scatter(x=result.bucket_labels, y=rx_vals, mode="lines+markers", name=f"{w_if.ifname} Rx (Mbps)", line=dict(color=wan_palette[c_idx % len(wan_palette)], width=2.2, dash="dot"))
            )
            c_idx += 1
        fig_wan.update_layout(
            title="15-Min Peak WAN Interface Throughput (Mbps) Over Time (EST)",
            xaxis_title="Time (EST)",
            yaxis_title="Throughput (Mbps)",
            hovermode="x unified",
            height=360,
            legend=dict(orientation="h", yanchor="bottom", y=1.04, xanchor="left", x=0),
            margin=dict(l=65, r=30, t=65, b=55),
            template="plotly_white",
        )
        wan_chart_html = fig_wan.to_html(full_html=False, include_plotlyjs=False)
        wan_rows_html = "".join(
            f"<tr><td><b>{_esc(w.ifname)}</b></td><td>{_esc(w.color)}</td>"
            f"<td>{f'{w.speed_mbps:.0f} Mbps' if w.speed_mbps > 0 else 'N/A'}</td>"
            f"<td>{w.peak_tx_mbps:.2f} Mbps</td><td>{w.peak_rx_mbps:.2f} Mbps</td>"
            f"<td><b>{w.peak_util_pct:.1f}%</b></td><td>{w.total_errors}</td><td>{w.total_drops}</td>"
            f"<td class='{'sev-recovered' if 'Clean' in w.diagnosis else 'sev-breach'}'>{_esc(w.diagnosis)}</td></tr>"
            for w in result.wan_interfaces
        )
    else:
        wan_chart_html = '<div style="color:#57606A;padding:12px;">No WAN interface statistics returned by vManage.</div>'
        wan_rows_html = '<tr><td colspan="9" style="text-align:center;color:#57606A;">No WAN interface data available.</td></tr>'

    # Raw Events Table Rows
    if result.raw_events:
        ev_rows_html = "".join(
            f"<tr><td>{_esc(e.timestamp_est)}</td><td>{_esc(e.event_type)}</td><td>{_esc(e.local_color)}</td>"
            f"<td>{_esc(e.remote_system_ip)}</td><td>{_esc(e.old_sla_classes)}</td><td>{_esc(e.new_sla_classes)}</td>"
            f"<td class='sev-{e.severity.lower()}'>{_esc(e.impact_summary)}</td></tr>"
            for e in result.raw_events
        )
    else:
        ev_rows_html = '<tr><td colspan="7" style="text-align:center;color:#107C10;font-weight:600;">Zero SLA or BFD events recorded.</td></tr>'

    verdict_cls = result.verdict_level.lower()

    full_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>SD-WAN SLA Dashboard — {_esc(result.device_hostname)} ({_esc(result.system_ip)})</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #F4F7FA; color: #1F2328; margin: 0; padding: 0; }}
    .header {{ background: #0D274D; color: #FFFFFF; padding: 22px 32px; }}
    .header h1 {{ margin: 0 0 6px 0; font-size: 22px; }}
    .header p {{ margin: 0; color: #CFE0F5; font-size: 13px; }}
    .container {{ max-width: 1280px; margin: 22px auto; padding: 0 20px 40px 20px; }}
    .verdict {{ border-radius: 8px; padding: 16px 20px; margin-bottom: 20px; border-left: 6px solid; }}
    .verdict.green {{ background: #DFF6DD; border-color: #107C10; color: #107C10; }}
    .verdict.amber {{ background: #FFF4CE; border-color: #E0A800; color: #7A5200; }}
    .verdict.red   {{ background: #FDE7E9; border-color: #D93025; color: #A4262C; }}
    .verdict h2 {{ margin: 0 0 6px 0; font-size: 16px; }}
    .verdict p {{ margin: 0; font-size: 13.5px; line-height: 1.45; }}
    .kpi-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(210px, 1fr)); gap: 14px; margin-bottom: 22px; }}
    .kpi {{ background: #FFFFFF; border: 1px solid #D0D7DE; border-radius: 8px; padding: 14px 16px; }}
    .kpi .label {{ font-size: 12px; color: #57606A; text-transform: uppercase; letter-spacing: 0.4px; }}
    .kpi .value {{ font-size: 18px; font-weight: 700; color: #0D274D; margin-top: 4px; }}
    .card {{ background: #FFFFFF; border: 1px solid #D0D7DE; border-radius: 8px; padding: 18px 20px; margin-bottom: 22px; }}
    .card h3 {{ margin: 0 0 12px 0; color: #0D274D; font-size: 16px; }}
    table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
    th {{ background: #005073; color: #FFFFFF; padding: 9px 10px; text-align: left; }}
    td {{ padding: 8px 10px; border-bottom: 1px solid #E5E9F0; }}
    tr:nth-child(even) {{ background: #F8FAFC; }}
    .sev-breach, .sev-bfd_down {{ color: #A4262C; font-weight: 700; background: #FDE7E9; }}
    .sev-recovered {{ color: #107C10; font-weight: 700; background: #DFF6DD; }}
    .empty-ok {{ padding: 18px; background: #DFF6DD; color: #107C10; font-weight: 600; border-radius: 6px; text-align: center; }}
  </style>
</head>
<body>
  <div class="header">
    <h1>Cisco SD-WAN SLA & Circuit Troubleshooting Dashboard</h1>
    <p>Device: <b>{_esc(result.device_hostname)}</b> ({_esc(result.system_ip)}) | Site ID: {_esc(result.site_id)} | vManage: {_esc(result.vmanage_host)} | Window: {_esc(result.start_est_str)} → {_esc(result.end_est_str)}</p>
  </div>
  <div class="container">
    <div class="verdict {verdict_cls}">
      <h2>{_esc(result.verdict_title)}</h2>
      <p>{_esc(result.verdict_summary)}</p>
    </div>

    <div class="kpi-grid">
      <div class="kpi"><div class="label">Probable Root Cause</div><div class="value" style="font-size:14px;">{_esc(result.probable_cause)}</div></div>
      <div class="kpi"><div class="label">SLA / BFD Events</div><div class="value">{result.total_sla_events} SLA | {result.total_bfd_downs} BFD Drops</div></div>
      <div class="kpi"><div class="label">Worst Affected Circuit</div><div class="value">{_esc(result.worst_transport)}</div></div>
      <div class="kpi"><div class="label">Worst Queue Out-of-SLA</div><div class="value">{_esc(result.worst_queue)} ({result.worst_queue_mins:.1f}m)</div></div>
      <div class="kpi"><div class="label">Peak Avg / Max Loss</div><div class="value">{result.peak_avg_loss:.1f}% / {result.peak_max_loss:.1f}%</div></div>
      <div class="kpi"><div class="label">Backup Health</div><div class="value">{_esc(result.backup_health_note)}</div></div>
    </div>

    <div class="card">{hm_html}</div>
    <div class="card">{metrics_html}</div>

    <div class="card">
      <h3>Application Traffic Failover Summary (EST)</h3>
      {app_chart_html}
      <div style="overflow-x:auto;margin-top:14px;">
        <table>
          <thead><tr><th>Queue (SLA)</th><th>Affected Applications / Traffic</th><th>Match Reference</th><th>Preferred</th><th>Moved To</th><th>Start (EST)</th><th>End (EST)</th><th>Duration</th><th>Count</th></tr></thead>
          <tbody>{app_rows_html}</tbody>
        </table>
      </div>
    </div>

    <div class="card">
      <h3>Top Observed Applications Active During SLA Breach Window (vManage DPI)</h3>
      <div style="overflow-x:auto;">
        <table>
          <thead><tr><th>Application Name</th><th>Family</th><th>Mapped Queue</th><th>Volume (MB)</th><th>Packets</th><th>VPN ID</th></tr></thead>
          <tbody>{dpi_rows_html}</tbody>
        </table>
      </div>
    </div>

    <div class="card">
      <h3>WAN Interface Utilization, Errors & Drops (Transport vs. Congestion)</h3>
      {wan_chart_html}
      <div style="overflow-x:auto;margin-top:14px;">
        <table>
          <thead><tr><th>WAN Interface</th><th>Color</th><th>Link Speed</th><th>Peak Tx</th><th>Peak Rx</th><th>Peak Util %</th><th>Errors</th><th>Drops</th><th>Diagnosis</th></tr></thead>
          <tbody>{wan_rows_html}</tbody>
        </table>
      </div>
    </div>

    <div class="card">
      <h3>Chronological SLA & BFD Events (EST)</h3>
      <div style="overflow-x:auto;">
        <table>
          <thead><tr><th>Timestamp (EST)</th><th>Event</th><th>Local Color</th><th>Remote Hub IP</th><th>Old SLA Classes</th><th>New SLA Classes</th><th>Impact Summary</th></tr></thead>
          <tbody>{ev_rows_html}</tbody>
        </table>
      </div>
    </div>
  </div>
</body>
</html>
"""
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(full_html)
    return output_path
