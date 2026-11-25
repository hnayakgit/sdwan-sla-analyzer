import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path
from zipfile import ZipFile

from openpyxl import load_workbook

from demo_data import get_demo_payloads
from excel_reporter import generate_excel_report
from sla_processor import analyze_sla_data


class ExcelChartTests(unittest.TestCase):
    def generate_report(self, hours, directory, healthy=False):
        (start, end, device, sla, tunnels, events, approute, policy, app_lists,
         dpi, interfaces, interface_stats) = get_demo_payloads(hours=hours)
        result = analyze_sla_data(
            vmanage_host="demo",
            device_info=device,
            duration_label=f"Last {hours} hours",
            start_utc=start,
            end_utc=end,
            sla_classes_raw=sla,
            site_tunnels_raw=tunnels,
            events_raw=events,
            approute_stats_raw=approute,
            policy_raw=policy,
            app_lists=app_lists,
            dpi_stats_raw=dpi,
            wan_interfaces_raw=interfaces,
            interface_stats_raw=interface_stats,
        )
        if healthy:
            result.heatmap_pct = {
                key: [0.0] * len(values)
                for key, values in result.heatmap_pct.items()
            }
        path = Path(directory) / "report.xlsx"
        generate_excel_report(result, str(path))
        return path

    def test_short_report_has_distinct_clustered_queue_series(self):
        for hours in (1, 4, 12, 24):
            with self.subTest(hours=hours), tempfile.TemporaryDirectory() as directory:
                path = self.generate_report(hours, directory)
                workbook = load_workbook(path)
                chart = workbook["Executive Summary"]._charts[0]
                self.assertEqual(chart.grouping, "clustered")
                self.assertEqual(chart.overlap, 0)
                self.assertEqual(chart.y_axis.scaling.min, 0)
                self.assertEqual(chart.y_axis.scaling.max, 100)
                self.assertFalse(chart.visible_cells_only)
                self.assertGreaterEqual(len(chart.series), 2)
                colors = [series.graphicalProperties.solidFill.srgbClr for series in chart.series]
                self.assertEqual(len(colors), len(set(colors)))
                for series in chart.series:
                    self.assertIn("15min Tunnel Metrics", series.val.numRef.f)
                workbook.close()

    def test_weekly_charts_include_hidden_hourly_sources(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.generate_report(168, directory)
            workbook = load_workbook(path)
            executive = workbook["Executive Summary"]
            chart = executive._charts[0]
            self.assertEqual(chart.grouping, "stacked")
            self.assertTrue(executive.column_dimensions["L"].hidden)
            self.assertGreater(len(chart.series), 0)
            self.assertTrue(any((cell.value or 0) > 0 for cell in executive["L"][1:]))
            self.assertIn("Executive Summary", chart.series[0].val.numRef.f)
            for current_chart in [chart, *workbook["15min Tunnel Metrics"]._charts]:
                self.assertFalse(current_chart.visible_cells_only)
                self.assertGreater(len(current_chart.series), 0)
            workbook.close()

            namespace = {"chart": "http://schemas.openxmlformats.org/drawingml/2006/chart"}
            with ZipFile(path) as archive:
                for chart_number in (1, 2, 3):
                    xml = ET.fromstring(archive.read(f"xl/charts/chart{chart_number}.xml"))
                    visibility = xml.find(".//chart:plotVisOnly", namespace)
                    self.assertIsNotNone(visibility)
                    self.assertEqual(visibility.get("val"), "0")

    def test_healthy_reports_explain_missing_outage_chart(self):
        for hours in (1, 4, 12, 24, 168):
            with self.subTest(hours=hours), tempfile.TemporaryDirectory() as directory:
                path = self.generate_report(hours, directory, healthy=True)
                workbook = load_workbook(path)
                executive = workbook["Executive Summary"]
                self.assertEqual(len(executive._charts), 0)
                messages = [cell.value for row in executive for cell in row if isinstance(cell.value, str)]
                self.assertIn("No SLA breaches detected in the selected time window.", messages)
                workbook.close()


if __name__ == "__main__":
    unittest.main()