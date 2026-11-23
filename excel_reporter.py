"""
Excel Report Generator (Approved v7 EST Executive Layout)
- Tab 1: Executive Summary (Verdict Card, Metadata, KPIs, Summary Tables, SLA Outage Timeline over EST)
- Tab 2: 15min SLA Heatmap (Color-coded Green -> Yellow -> Red % Out-of-SLA per Queue)
- Tab 3: 15min Tunnel Metrics (Loss %, Latency, Jitter table + Latency & Jitter Charts with clean EST baseline)
- Tab 4: App Failover Summary (Apps moved, backup transport, EST timestamps, Duration + clean Column Chart)
- Tab 5: Raw SLA & BFD Events (Chronological filterable audit log in EST)
"""

import openpyxl
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
from openpyxl.formatting.rule import ColorScaleRule, CellIsRule
from openpyxl.chart import BarChart, LineChart, Reference
from openpyxl.chart.marker import Marker
from openpyxl.chart.text import RichText
from openpyxl.drawing.text import Paragraph, ParagraphProperties, CharacterProperties, RichTextProperties
from openpyxl.utils import get_column_letter

from sla_processor import AnalysisResult, fmt_duration_short

# Corporate Palette
NAVY = "0D274D"
BLUE = "005073"
LIGHT_BLUE = "EBF3FA"
ZEBRA = "F8FAFC"
BORDER_GRAY = "D0D7DE"
AMBER_BG = "FFF4CE"
AMBER_BORDER = "E0A800"
AMBER_TXT = "7A5200"
RED_BG = "FDE7E9"
RED_BORDER = "D93025"
RED_TXT = "A4262C"
GREEN_BG = "DFF6DD"
GREEN_BORDER = "107C10"
GREEN_TXT = "107C10"
WHITE = "FFFFFF"
DARK_TXT = "1F2328"
MUTED_TXT = "57606A"

thin_side = Side(style="thin", color=BORDER_GRAY)
thin_border = Border(left=thin_side, right=thin_side, top=thin_side, bottom=thin_side)

title_font = Font(name="Calibri", size=16, bold=True, color=WHITE)
subtitle_font = Font(name="Calibri", size=10, italic=True, color="D6E4F0")
section_font = Font(name="Calibri", size=12, bold=True, color=NAVY)
header_font = Font(name="Calibri", size=10, bold=True, color=WHITE)
bold_font = Font(name="Calibri", size=10, bold=True, color=DARK_TXT)
regular_font = Font(name="Calibri", size=10, color=DARK_TXT)

navy_fill = PatternFill("solid", fgColor=NAVY)
blue_fill = PatternFill("solid", fgColor=BLUE)
light_blue_fill = PatternFill("solid", fgColor=LIGHT_BLUE)
zebra_fill = PatternFill("solid", fgColor=ZEBRA)
red_fill = PatternFill("solid", fgColor=RED_BG)
green_fill = PatternFill("solid", fgColor=GREEN_BG)
white_fill = PatternFill("solid", fgColor=WHITE)


def _style_table_header(ws, row, start_col, end_col, height=28):
    ws.row_dimensions[row].height = height
    for c in range(start_col, end_col + 1):
        cell = ws.cell(row=row, column=c)
        cell.font = header_font
        cell.fill = blue_fill
        cell.alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)
        cell.border = thin_border


def _make_axis_text(font_size_pt=9):
    cp = CharacterProperties(sz=font_size_pt * 100, b=False)
    pp = ParagraphProperties(defRPr=cp)
    return RichText(bodyPr=RichTextProperties(), p=[Paragraph(pPr=pp, endParaRPr=cp)])


def _calc_tick_skip(num_buckets: int) -> int:
    """Keep X-axis baseline crisp (~8-12 ticks) regardless of 1h, 4h, 12h, 24h, or 1 week."""
    if num_buckets <= 8:
        return 1
    if num_buckets <= 20:
        return 2    # 30-min marks (08:00, 08:30, 09:00...)
    if num_buckets <= 52:
        return 4    # 1-hour marks
    if num_buckets <= 100:
        return 8    # 2-hour marks
    return max(16, num_buckets // 12)  # ~12 clean marks across 1 week


def _configure_time_chart(ch, y_title, tick_skip=2, show_legend=True, height_cm=12.5, width_cm=28):
    ch.width = width_cm
    ch.height = height_cm
    ch.style = 2

    if ch.title:
        ch.title.overlay = False

    if show_legend and ch.legend:
        ch.legend.position = "t"
        ch.legend.overlay = False
    else:
        ch.legend = None

    ch.x_axis.delete = False
    ch.y_axis.delete = False
    ch.x_axis.axPos = "b"
    ch.y_axis.axPos = "l"
    ch.x_axis.tickLblPos = "low"
    ch.y_axis.tickLblPos = "nextTo"
    ch.x_axis.tickLblSkip = tick_skip
    ch.x_axis.tickMarkSkip = tick_skip
    ch.x_axis.txPr = _make_axis_text(font_size_pt=9)
    ch.y_axis.txPr = _make_axis_text(font_size_pt=9)

    ch.x_axis.title = "Time (EST)"
    ch.x_axis.title.overlay = False
    if y_title:
        ch.y_axis.title = y_title
        ch.y_axis.title.overlay = False


def _style_line_series(series, hex_color, dashed=False, width_emu=26000):
    series.graphicalProperties.line.solidFill = hex_color
    series.graphicalProperties.line.width = width_emu
    if dashed:
        series.graphicalProperties.line.dashStyle = "dash"
    else:
        series.marker = Marker(symbol="circle", size=5)
        series.marker.graphicalProperties.solidFill = hex_color
        series.marker.graphicalProperties.line.solidFill = WHITE


def generate_excel_report(result: AnalysisResult, output_path: str) -> str:
    wb = openpyxl.Workbook()
    num_buckets = len(result.bucket_labels)
    tick_skip = _calc_tick_skip(num_buckets)
    sla_names = list(result.sla_classes.keys()) if result.sla_classes else ["Default"]

    # Determine primary & backup colors for comparison charts
    primary_color = result.colors[0] if result.colors else "mpls"
    if result.worst_transport != "None (All Healthy)" and " -> " in result.worst_transport:
        primary_color = result.worst_transport.split(" -> ")[0].strip()
    other_colors = [c for c in result.colors if c != primary_color]
    backup_color = other_colors[0] if other_colors else None

    # ==========================================================================
    # TAB 1: EXECUTIVE SUMMARY
    # ==========================================================================
    ws1 = wb.active
    ws1.title = "Executive Summary"
    ws1.views.sheetView[0].showGridLines = False

    ws1.merge_cells("A1:I1")
    ws1["A1"] = "Cisco SD-WAN SLA & Circuit Troubleshooting Report"
    ws1["A1"].font = title_font
    ws1["A1"].fill = navy_fill
    ws1["A1"].alignment = Alignment(horizontal="left", vertical="center", indent=1)
    ws1.row_dimensions[1].height = 36

    ws1.merge_cells("A2:I2")
    ws1["A2"] = (
        f"On-Demand Single-Device Analysis from vManage ({result.vmanage_host})  |  "
        "All Timestamps in EST (America/New_York)  |  15-Minute Resolution"
    )
    ws1["A2"].font = subtitle_font
    ws1["A2"].fill = navy_fill
    ws1["A2"].alignment = Alignment(horizontal="left", vertical="center", indent=1)
    ws1.row_dimensions[2].height = 22
    ws1.row_dimensions[3].height = 10

    # Dynamic Verdict Card Colors
    verdict_palette = {
        "RED": (RED_BG, RED_BORDER, RED_TXT),
        "AMBER": (AMBER_BG, AMBER_BORDER, AMBER_TXT),
        "GREEN": (GREEN_BG, GREEN_BORDER, GREEN_TXT),
    }
    v_bg, v_bdr, v_txt = verdict_palette.get(result.verdict_level, (AMBER_BG, AMBER_BORDER, AMBER_TXT))
    v_fill = PatternFill("solid", fgColor=v_bg)
    v_side = Side(style="medium", color=v_bdr)

    ws1.merge_cells("A4:I4")
    ws1["A4"] = result.verdict_title
    ws1["A4"].font = Font(name="Calibri", size=12, bold=True, color=v_txt)
    ws1["A4"].fill = v_fill
    ws1["A4"].alignment = Alignment(horizontal="left", vertical="center", indent=1)
    ws1.row_dimensions[4].height = 30

    ws1.merge_cells("A5:I5")
    ws1["A5"] = result.verdict_summary
    ws1["A5"].font = Font(name="Calibri", size=10, color=v_txt)
    ws1["A5"].fill = v_fill
    ws1["A5"].alignment = Alignment(horizontal="left", vertical="center", wrap_text=True, indent=1)
    ws1.row_dimensions[5].height = 56
    for r in (4, 5):
        for c in range(1, 10):
            ws1.cell(r, c).border = Border(
                left=v_side if c == 1 else None,
                right=v_side if c == 9 else None,
                top=v_side if r == 4 else thin_side,
                bottom=v_side if r == 5 else None,
            )

    ws1.row_dimensions[6].height = 12
    ws1["A7"] = "Device & Analysis Scope"
    ws1["A7"].font = section_font
    ws1["F7"] = "Key Health KPIs"
    ws1["F7"].font = section_font
    ws1.row_dimensions[7].height = 24

    meta_rows = [
        ("Device Hostname", result.device_hostname),
        ("cEdge System IP", result.system_ip),
        ("Site ID", result.site_id),
        ("vManage Controller", result.vmanage_host),
        ("Analysis Window (EST)", f"{result.start_est_str}  to  {result.end_est_str}"),
        ("Duration / Resolution", f"{result.duration_label}  |  {num_buckets} x 15-Min Buckets"),
        ("Monitored Transports", ", ".join(result.colors) if result.colors else "None detected"),
    ]

    kpi_rows = [
        ("Total SLA-Change Events", f"{result.total_sla_events} Events"),
        ("BFD Tunnel Down Events", f"{result.total_bfd_downs} Drops"),
        ("Worst Affected Circuit", result.worst_transport),
        ("Peak Avg / Max Packet Loss", f"{result.peak_avg_loss:.1f}% Avg  |  {result.peak_max_loss:.1f}% Max  ({result.peak_loss_time})"),
        ("Peak Avg Latency / Jitter", f"{result.peak_avg_latency:.0f} ms Latency  |  {result.peak_avg_jitter:.0f} ms Jitter"),
        ("Worst Affected Queue (SLA)", f"{result.worst_queue} ({result.worst_queue_mins:.1f} mins Out-of-SLA)"),
        ("Backup Circuit Health", result.backup_health_note),
    ]

    for idx, (k, v) in enumerate(meta_rows, start=8):
        ws1.row_dimensions[idx].height = 22
        ws1.cell(idx, 1, k).font = bold_font
        ws1.cell(idx, 1).fill = light_blue_fill
        ws1.cell(idx, 1).alignment = Alignment(vertical="center", indent=1)
        ws1.merge_cells(start_row=idx, start_column=2, end_row=idx, end_column=4)
        ws1.cell(idx, 2, v).font = regular_font
        ws1.cell(idx, 2).fill = white_fill
        ws1.cell(idx, 2).alignment = Alignment(vertical="center", indent=1)
        for c in range(1, 5):
            ws1.cell(idx, c).border = thin_border

    for idx, (k, v) in enumerate(kpi_rows, start=8):
        ws1.cell(idx, 6, k).font = bold_font
        ws1.cell(idx, 6).fill = light_blue_fill
        ws1.cell(idx, 6).alignment = Alignment(vertical="center", indent=1)
        ws1.merge_cells(start_row=idx, start_column=7, end_row=idx, end_column=9)
        val_cell = ws1.cell(idx, 7, v)
        val_cell.font = regular_font
        val_cell.fill = white_fill
        val_cell.alignment = Alignment(vertical="center", indent=1)
        if "100% In-SLA" in v:
            val_cell.fill = green_fill
            val_cell.font = Font(name="Calibri", size=10, bold=True, color=GREEN_TXT)
        elif k == "Peak Avg / Max Packet Loss" and result.peak_avg_loss >= 1.0:
            val_cell.fill = red_fill
            val_cell.font = Font(name="Calibri", size=10, bold=True, color=RED_TXT)
        for c in range(6, 10):
            ws1.cell(idx, c).border = thin_border

    ws1.row_dimensions[15].height = 14
    ws1["A16"] = "Out-of-SLA Duration by Transport & Queue (Minutes)"
    ws1["A16"].font = section_font
    ws1["F16"] = "Impacted Applications Moved to Backup"
    ws1["F16"].font = section_font
    ws1.row_dimensions[16].height = 24

    # Up to 3 top SLA classes in Executive Summary table
    top_slas = sla_names[:3]
    summary_headers = ["Transport -> Hub"] + [f"{q} (m)" for q in top_slas]
    while len(summary_headers) < 4:
        summary_headers.append("-")
    for c, h in enumerate(summary_headers, start=1):
        ws1.cell(17, c, h)
    _style_table_header(ws1, 17, 1, 4, height=26)

    display_tunnels = result.tunnels[:6] if result.tunnels else [("N/A", "N/A")]
    for i, (color, rip) in enumerate(display_tunnels, start=18):
        ws1.row_dimensions[i].height = 22
        row_vals = [f"{color} -> Hub {rip}"]
        for q in top_slas:
            row_vals.append(round(result.total_out_mins.get((color, rip, q), 0.0), 1))
        while len(row_vals) < 4:
            row_vals.append(0.0)
        for c, val in enumerate(row_vals, start=1):
            cell = ws1.cell(i, c, val)
            cell.font = bold_font if (c > 1 and isinstance(val, (int, float)) and val > 0) else regular_font
            cell.border = thin_border
            cell.alignment = Alignment(horizontal="left" if c == 1 else "center", vertical="center")
            if c > 1:
                cell.number_format = "0.0"
            cell.fill = zebra_fill if i % 2 == 1 else white_fill

    # Right summary table: Top App Failovers
    app_snap_headers = ["Application", "Queue", "Moved To", "Duration"]
    for c, h in enumerate(app_snap_headers, start=6):
        ws1.cell(17, c, h)
    _style_table_header(ws1, 17, 6, 9, height=26)

    if result.app_failovers:
        snap_rows = [
            (f"{a.application} ({a.app_list})", a.sla_class, a.moved_to_color, fmt_duration_short(a.duration_seconds))
            for a in result.app_failovers[: max(4, len(display_tunnels))]
        ]
    else:
        snap_rows = [("No Application Failover", "All Queues", "Stayed on Primary", "0m 00s")]

    for i, row_vals in enumerate(snap_rows, start=18):
        ws1.row_dimensions[i].height = 22
        for c, val in enumerate(row_vals, start=6):
            cell = ws1.cell(i, c, val)
            cell.font = bold_font if c == 9 and val != "0m 00s" else regular_font
            cell.border = thin_border
            cell.alignment = Alignment(horizontal="left" if c == 6 else "center", vertical="center")
            cell.fill = zebra_fill if i % 2 == 1 else white_fill

    ws1.column_dimensions["A"].width = 28
    ws1.column_dimensions["B"].width = 16
    ws1.column_dimensions["C"].width = 16
    ws1.column_dimensions["D"].width = 15
    ws1.column_dimensions["E"].width = 3.5
    ws1.column_dimensions["F"].width = 32
    ws1.column_dimensions["G"].width = 15
    ws1.column_dimensions["H"].width = 18
    ws1.column_dimensions["I"].width = 15

    # ==========================================================================
    # TAB 2: 15-MIN SLA HEATMAP (PER QUEUE)
    # ==========================================================================
    ws2 = wb.create_sheet("15min SLA Heatmap")
    ws2.views.sheetView[0].showGridLines = True

    last_hm_col = 4 + num_buckets
    last_hm_letter = get_column_letter(last_hm_col)
    ws2.merge_cells(f"A1:{last_hm_letter}1")
    ws2["A1"] = "15-Minute SLA Violation Heatmap (EST) — % of Time Out-of-SLA per Queue"
    ws2["A1"].font = title_font
    ws2["A1"].fill = navy_fill
    ws2["A1"].alignment = Alignment(horizontal="left", vertical="center", indent=1)
    ws2.row_dimensions[1].height = 32

    ws2.merge_cells(f"A2:{last_hm_letter}2")
    ws2["A2"] = "All Time Columns in EST (America/New_York)  |  '-' = 0% (100% Healthy)  |  Yellow/Red = % of 15-Min Window Out-of-SLA"
    ws2["A2"].font = subtitle_font
    ws2["A2"].fill = navy_fill
    ws2["A2"].alignment = Alignment(horizontal="left", vertical="center", indent=1)
    ws2.row_dimensions[2].height = 20

    headers2 = ["Local Color", "Remote Hub IP", "Queue (SLA Class)"] + result.bucket_labels + ["Total Out-of-SLA (mins)"]
    for c, h in enumerate(headers2, start=1):
        ws2.cell(4, c, h)
    _style_table_header(ws2, 4, 1, len(headers2), height=28)

    hm_row = 5
    for color, rip in result.tunnels:
        for q in sla_names:
            ws2.row_dimensions[hm_row].height = 22
            ws2.cell(hm_row, 1, color).font = bold_font
            ws2.cell(hm_row, 2, rip).font = regular_font
            ws2.cell(hm_row, 3, q).font = bold_font
            for c in range(1, 4):
                ws2.cell(hm_row, c).alignment = Alignment(horizontal="center", vertical="center")
                ws2.cell(hm_row, c).border = thin_border
            pcts = result.heatmap_pct.get((color, rip, q), [0.0] * num_buckets)
            for idx, pct in enumerate(pcts):
                cell = ws2.cell(hm_row, 4 + idx, pct / 100.0)
                cell.number_format = '0%;-0%;"-"'
                cell.alignment = Alignment(horizontal="center", vertical="center")
                cell.font = bold_font if pct > 0 else Font(name="Calibri", size=10, color=MUTED_TXT)
                cell.border = thin_border
            t_cell = ws2.cell(hm_row, last_hm_col, round(result.total_out_mins.get((color, rip, q), 0.0), 1))
            t_cell.number_format = "0.0"
            t_cell.alignment = Alignment(horizontal="center", vertical="center")
            t_cell.font = bold_font
            t_cell.border = thin_border
            hm_row += 1

    if hm_row > 5:
        hm_data_end = get_column_letter(3 + num_buckets)
        color_scale = ColorScaleRule(
            start_type="num", start_value=0, start_color="DFF6DD",
            mid_type="num", mid_value=0.45, mid_color="FFE699",
            end_type="num", end_value=1.0, end_color="F8696B",
        )
        ws2.conditional_formatting.add(f"D5:{hm_data_end}{hm_row - 1}", color_scale)

    ws2.freeze_panes = "D5"
    ws2.column_dimensions["A"].width = 16
    ws2.column_dimensions["B"].width = 16
    ws2.column_dimensions["C"].width = 18
    for c in range(4, 4 + num_buckets):
        ws2.column_dimensions[get_column_letter(c)].width = 8.5
    ws2.column_dimensions[last_hm_letter].width = 23

    # ==========================================================================
    # TAB 3: 15-MIN TUNNEL METRICS (PRIMARY vs BACKUP ON PRIMARY HUB)
    # ==========================================================================
    ws3 = wb.create_sheet("15min Tunnel Metrics")
    ws3.views.sheetView[0].showGridLines = True

    # Thresholds from strictest SLA class
    strict_sla = min(result.sla_classes.values(), key=lambda x: x.loss) if result.sla_classes else None
    loss_limit = strict_sla.loss if strict_sla else 1.0
    lat_limit = strict_sla.latency if strict_sla else 100.0
    jit_limit = strict_sla.jitter if strict_sla else 20.0
    strict_name = strict_sla.name if strict_sla else "SLA"

    # Two top queues for SLA Outage Timeline chart on Tab 1
    q1_name = sla_names[0] if len(sla_names) >= 1 else "Default"
    q2_name = sla_names[1] if len(sla_names) >= 2 else None

    bk_label = backup_color if backup_color else "Backup"
    headers3 = [
        "Time (EST)",
        f"{primary_color} Avg Loss (%)",
        f"{primary_color} Max Loss (%)",
        f"{bk_label} Avg Loss (%)",
        f"{primary_color} Avg Latency (ms)",
        f"{bk_label} Avg Latency (ms)",
        f"{primary_color} Avg Jitter (ms)",
        f"{bk_label} Avg Jitter (ms)",
        f"{strict_name} Loss Limit (%)",
        f"{strict_name} Latency Limit (ms)",
        f"{strict_name} Jitter Limit (ms)",
        f"{primary_color} {q1_name} Outage (%)",
    ]
    if q2_name:
        headers3.append(f"{primary_color} {q2_name} Outage (%)")

    last_m_letter = get_column_letter(len(headers3))
    ws3.merge_cells(f"A1:{last_m_letter}1")
    ws3["A1"] = f"15-Minute Tunnel Performance Metrics (EST | Hub {result.primary_hub_ip}) — Loss %, Latency (ms), Jitter (ms)"
    ws3["A1"].font = title_font
    ws3["A1"].fill = navy_fill
    ws3["A1"].alignment = Alignment(horizontal="left", vertical="center", indent=1)
    ws3.row_dimensions[1].height = 32

    for c, h in enumerate(headers3, start=1):
        ws3.cell(3, c, h)
    _style_table_header(ws3, 3, 1, len(headers3), height=32)

    p_metrics = result.tunnel_metrics.get((primary_color, result.primary_hub_ip), [])
    b_metrics = result.tunnel_metrics.get((backup_color, result.primary_hub_ip), []) if backup_color else []
    q1_pcts = result.heatmap_pct.get((primary_color, result.primary_hub_ip, q1_name), [0.0] * num_buckets)
    q2_pcts = result.heatmap_pct.get((primary_color, result.primary_hub_ip, q2_name), [0.0] * num_buckets) if q2_name else []

    max_lat_seen = lat_limit
    max_jit_seen = jit_limit

    for i in range(num_buckets):
        r = 4 + i
        ws3.row_dimensions[r].height = 20
        pm = p_metrics[i] if i < len(p_metrics) else {"avg_loss": 0.0, "max_loss": 0.0, "avg_latency": 0.0, "avg_jitter": 0.0}
        bm = b_metrics[i] if i < len(b_metrics) else {"avg_loss": 0.0, "max_loss": 0.0, "avg_latency": 0.0, "avg_jitter": 0.0}
        max_lat_seen = max(max_lat_seen, pm["avg_latency"], bm["avg_latency"])
        max_jit_seen = max(max_jit_seen, pm["avg_jitter"], bm["avg_jitter"])

        vals = [
            result.bucket_labels[i],
            pm["avg_loss"], pm["max_loss"], bm["avg_loss"],
            pm["avg_latency"], bm["avg_latency"],
            pm["avg_jitter"], bm["avg_jitter"],
            loss_limit, lat_limit, jit_limit,
            q1_pcts[i],
        ]
        if q2_name:
            vals.append(q2_pcts[i])

        for c, v in enumerate(vals, start=1):
            cell = ws3.cell(r, c, v)
            cell.font = bold_font if c == 1 else regular_font
            cell.border = thin_border
            cell.alignment = Alignment(horizontal="center", vertical="center")
            if c in (2, 3, 4, 9):
                cell.number_format = '0.0"%"'
            elif c in (12, 13):
                cell.number_format = '0"%"'
            cell.fill = zebra_fill if r % 2 == 0 else white_fill

    last_data_row = 3 + num_buckets
    red_rule_loss = CellIsRule(operator="greaterThan", formula=[str(loss_limit)], fill=red_fill, font=Font(bold=True, color=RED_TXT))
    red_rule_lat = CellIsRule(operator="greaterThan", formula=[str(lat_limit)], fill=red_fill, font=Font(bold=True, color=RED_TXT))
    red_rule_jit = CellIsRule(operator="greaterThan", formula=[str(jit_limit)], fill=red_fill, font=Font(bold=True, color=RED_TXT))
    ws3.conditional_formatting.add(f"B4:D{last_data_row}", red_rule_loss)
    ws3.conditional_formatting.add(f"E4:F{last_data_row}", red_rule_lat)
    ws3.conditional_formatting.add(f"G4:H{last_data_row}", red_rule_jit)

    for c_idx in range(1, len(headers3) + 1):
        ws3.column_dimensions[get_column_letter(c_idx)].width = 20 if c_idx > 1 else 14

    # TAB 1 CHART: SLA Outage Timeline Over Time (EST) — placed safely below summary tables
    chart1_row = max(24, 19 + max(len(display_tunnels), len(snap_rows)) + 2)
    exec_sla_chart = BarChart()
    exec_sla_chart.type = "col"
    exec_sla_chart.grouping = "clustered"
    exec_sla_chart.title = f"SLA Outage Timeline Over Time (EST) — % Out-of-SLA per Queue (Hub {result.primary_hub_ip})"
    exec_sla_chart.y_axis.scaling.min = 0
    exec_sla_chart.y_axis.scaling.max = 100
    max_q_col = 13 if q2_name else 12
    exec_sla_chart.add_data(Reference(ws3, min_col=12, min_row=3, max_col=max_q_col, max_row=last_data_row), titles_from_data=True)
    exec_sla_chart.set_categories(Reference(ws3, min_col=1, min_row=4, max_row=last_data_row))
    exec_sla_chart.series[0].graphicalProperties.solidFill = "D93025"
    if q2_name and len(exec_sla_chart.series) > 1:
        exec_sla_chart.series[1].graphicalProperties.solidFill = "E67C00"
    _configure_time_chart(exec_sla_chart, y_title="% Time Out of SLA", tick_skip=tick_skip, show_legend=True)
    ws1.add_chart(exec_sla_chart, f"A{chart1_row}")

    # TAB 3 CHARTS: Latency & Jitter with clean EST baseline
    chart3_start = last_data_row + 3
    lat_chart = LineChart()
    lat_chart.title = f"15-Min Average Latency (ms) Over Time (EST) — {primary_color} vs {bk_label}"
    lat_chart.y_axis.scaling.min = 0
    lat_chart.y_axis.scaling.max = int(max_lat_seen * 1.25) + 10
    lat_chart.add_data(Reference(ws3, min_col=5, min_row=3, max_col=6, max_row=last_data_row), titles_from_data=True)
    lat_chart.add_data(Reference(ws3, min_col=10, min_row=3, max_col=10, max_row=last_data_row), titles_from_data=True)
    lat_chart.set_categories(Reference(ws3, min_col=1, min_row=4, max_row=last_data_row))
    _style_line_series(lat_chart.series[0], "D93025")
    _style_line_series(lat_chart.series[1], "005073")
    _style_line_series(lat_chart.series[2], "E67C00", dashed=True, width_emu=20000)
    _configure_time_chart(lat_chart, y_title="Latency (ms)", tick_skip=tick_skip, show_legend=True)
    ws3.add_chart(lat_chart, f"A{chart3_start}")

    jit_chart = LineChart()
    jit_chart.title = f"15-Min Average Jitter (ms) Over Time (EST) — {primary_color} vs {bk_label}"
    jit_chart.y_axis.scaling.min = 0
    jit_chart.y_axis.scaling.max = int(max_jit_seen * 1.25) + 5
    jit_chart.add_data(Reference(ws3, min_col=7, min_row=3, max_col=8, max_row=last_data_row), titles_from_data=True)
    jit_chart.add_data(Reference(ws3, min_col=11, min_row=3, max_col=11, max_row=last_data_row), titles_from_data=True)
    jit_chart.set_categories(Reference(ws3, min_col=1, min_row=4, max_row=last_data_row))
    _style_line_series(jit_chart.series[0], "D93025")
    _style_line_series(jit_chart.series[1], "005073")
    _style_line_series(jit_chart.series[2], "E67C00", dashed=True, width_emu=20000)
    _configure_time_chart(jit_chart, y_title="Jitter (ms)", tick_skip=tick_skip, show_legend=True)
    ws3.add_chart(jit_chart, f"A{chart3_start + 27}")

    # ==========================================================================
    # TAB 4: APPLICATION FAILOVER SUMMARY (APPROVED v7 CLEAN CHART — NO INNER LABELS)
    # ==========================================================================
    ws4 = wb.create_sheet("App Failover Summary")
    ws4.views.sheetView[0].showGridLines = True

    ws4.merge_cells("A1:J1")
    ws4["A1"] = "Application Traffic Failover Summary (EST | Derived from AAR Policy + SLA-Change Events)"
    ws4["A1"].font = title_font
    ws4["A1"].fill = navy_fill
    ws4["A1"].alignment = Alignment(horizontal="left", vertical="center", indent=1)
    ws4.row_dimensions[1].height = 32

    headers4 = [
        "Application", "App-List", "Queue (SLA Class)", "Preferred Color",
        "Moved To (Backup)", "Failover Start (EST)", "Failover End (EST)",
        "Duration (mins)", "Duration (HH:MM:SS)", "Failover Count"
    ]
    for c, h in enumerate(headers4, start=1):
        ws4.cell(3, c, h)
    _style_table_header(ws4, 3, 1, len(headers4), height=28)

    if result.app_failovers:
        for idx, a in enumerate(result.app_failovers, start=4):
            ws4.row_dimensions[idx].height = 22
            vals = [
                a.application, a.app_list, a.sla_class, a.preferred_color,
                a.moved_to_color, a.start_est, a.end_est,
                a.duration_mins, a.duration_hms, a.failover_count
            ]
            for c, v in enumerate(vals, start=1):
                cell = ws4.cell(idx, c, v)
                cell.font = bold_font if c in (1, 8) else regular_font
                cell.border = thin_border
                cell.alignment = Alignment(horizontal="left" if c == 1 else "center", vertical="center")
                if c == 8:
                    cell.number_format = "0.0"
                cell.fill = zebra_fill if idx % 2 == 0 else white_fill

        app_end_row = 3 + len(result.app_failovers)
        max_dur = max(a.duration_mins for a in result.app_failovers)

        app_chart = BarChart()
        app_chart.type = "col"
        app_chart.grouping = "clustered"
        app_chart.title = "Application Failover Duration on Backup Transport (Minutes)"
        app_chart.style = 2
        app_chart.legend = None
        app_chart.width = 25
        app_chart.height = 12
        app_chart.y_axis.scaling.min = 0
        app_chart.y_axis.scaling.max = max(5, int(max_dur * 1.25) + 2)
        app_chart.add_data(Reference(ws4, min_col=8, min_row=3, max_row=app_end_row), titles_from_data=True)
        app_chart.set_categories(Reference(ws4, min_col=1, min_row=4, max_row=app_end_row))
        app_chart.series[0].graphicalProperties.solidFill = BLUE
        app_chart.x_axis.delete = False
        app_chart.y_axis.delete = False
        app_chart.x_axis.axPos = "b"
        app_chart.y_axis.axPos = "l"
        app_chart.x_axis.tickLblPos = "low"
        app_chart.y_axis.tickLblPos = "nextTo"
        app_chart.x_axis.txPr = _make_axis_text(font_size_pt=10)
        app_chart.y_axis.txPr = _make_axis_text(font_size_pt=9)
        app_chart.y_axis.title = "Duration (Minutes)"
        app_chart.y_axis.title.overlay = False
        app_chart.y_axis.majorGridlines = None
        ws4.add_chart(app_chart, f"A{app_end_row + 3}")
    else:
        ws4.merge_cells("A4:J4")
        ws4["A4"] = "No application failover events occurred during the selected EST time window."
        ws4["A4"].font = Font(name="Calibri", size=11, bold=True, color=GREEN_TXT)
        ws4["A4"].fill = green_fill
        ws4["A4"].alignment = Alignment(horizontal="center", vertical="center")
        ws4.row_dimensions[4].height = 28

    col_widths_4 = [20, 16, 17, 16, 20, 25, 25, 16, 19, 15]
    for c_idx, w in enumerate(col_widths_4, start=1):
        ws4.column_dimensions[get_column_letter(c_idx)].width = w

    # ==========================================================================
    # TAB 5: RAW SLA & BFD EVENTS
    # ==========================================================================
    ws5 = wb.create_sheet("Raw SLA & BFD Events")
    ws5.views.sheetView[0].showGridLines = True

    ws5.merge_cells("A1:G1")
    ws5["A1"] = "Chronological vManage SLA-Change & BFD Events (All Timestamps in EST)"
    ws5["A1"].font = title_font
    ws5["A1"].fill = navy_fill
    ws5["A1"].alignment = Alignment(horizontal="left", vertical="center", indent=1)
    ws5.row_dimensions[1].height = 32

    headers5 = ["Timestamp (EST)", "Event Type", "Local Color", "Remote Hub IP", "Old SLA Classes", "New SLA Classes", "Impact Summary"]
    for c, h in enumerate(headers5, start=1):
        ws5.cell(3, c, h)
    _style_table_header(ws5, 3, 1, len(headers5), height=28)

    if result.raw_events:
        for idx, ev in enumerate(result.raw_events, start=4):
            ws5.row_dimensions[idx].height = 22
            vals = [
                ev.timestamp_est, ev.event_type, ev.local_color,
                ev.remote_system_ip, ev.old_sla_classes, ev.new_sla_classes, ev.impact_summary
            ]
            for c, v in enumerate(vals, start=1):
                cell = ws5.cell(idx, c, v)
                cell.font = regular_font
                cell.border = thin_border
                cell.alignment = Alignment(horizontal="left" if c in (5, 6, 7) else "center", vertical="center")
                if c == 7:
                    if ev.severity in ("BREACH", "BFD_DOWN"):
                        cell.fill = red_fill
                        cell.font = Font(name="Calibri", size=10, bold=True, color=RED_TXT)
                    elif ev.severity == "RECOVERED":
                        cell.fill = green_fill
                        cell.font = Font(name="Calibri", size=10, bold=True, color=GREEN_TXT)
                else:
                    cell.fill = zebra_fill if idx % 2 == 0 else white_fill
        ws5.auto_filter.ref = f"A3:G{3 + len(result.raw_events)}"
    else:
        ws5.merge_cells("A4:G4")
        ws5["A4"] = "Zero SLA-change or BFD state-change events recorded during this window."
        ws5["A4"].font = Font(name="Calibri", size=11, bold=True, color=GREEN_TXT)
        ws5["A4"].fill = green_fill
        ws5["A4"].alignment = Alignment(horizontal="center", vertical="center")
        ws5.row_dimensions[4].height = 28

    col_widths_5 = [25, 16, 14, 16, 32, 32, 56]
    for c_idx, w in enumerate(col_widths_5, start=1):
        ws5.column_dimensions[get_column_letter(c_idx)].width = w

    wb.save(output_path)
    return output_path
