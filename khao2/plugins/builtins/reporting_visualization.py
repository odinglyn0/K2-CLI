"""Reporting and visualization plugin for comprehensive analysis reports."""
import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
from khao2.plugins import (
    ExporterPlugin, PluginMetadata, PluginContext,
    PluginError
)


@dataclass
class ReportTemplate:
    """Represents a report template."""
    template_id: str
    name: str
    description: str
    format: str  # 'html', 'pdf', 'json', 'csv'
    template_data: str
    created_at: float
    metadata: Dict[str, Any] = None

    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}


@dataclass
class DashboardConfig:
    """Configuration for dashboard generation."""
    include_charts: bool = True
    include_trends: bool = True
    include_anomalies: bool = True
    time_range_days: int = 30
    refresh_interval_minutes: int = 60
    max_items_per_section: int = 50


@dataclass
class ReportData:
    """Data structure for report generation."""
    title: str
    summary: Dict[str, Any]
    scans: List[Dict[str, Any]]
    anomalies: List[Dict[str, Any]]
    trends: Dict[str, Any]
    recommendations: List[Dict[str, Any]]
    generated_at: float
    metadata: Dict[str, Any] = None

    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}


class ReportingVisualizationPlugin(ExporterPlugin):
    """Plugin for comprehensive reporting and visualization."""

    def __init__(self):
        self.config: DashboardConfig = DashboardConfig()
        self.templates: Dict[str, ReportTemplate] = {}
        self.api_client = None
        self.account_service = None

    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="reporting_visualization",
            version="1.0.0",
            description="Comprehensive reporting and visualization system",
            author="Khao2 Team",
            plugin_type="exporter",
            entry_point="khao2.plugins.builtins.reporting_visualization.ReportingVisualizationPlugin",
            config_schema={
                "include_charts": {
                    "type": "boolean",
                    "default": True,
                    "description": "Include charts in reports"
                },
                "include_trends": {
                    "type": "boolean",
                    "default": True,
                    "description": "Include trend analysis"
                },
                "time_range_days": {
                    "type": "integer",
                    "default": 30,
                    "description": "Default time range for reports in days"
                }
            }
        )

    def initialize(self, context: PluginContext) -> None:
        """Initialize the reporting plugin."""
        self.api_client = context.services.get('api_client')
        self.account_service = context.services.get('account_service')

        # Load configuration
        plugin_config = context.config.get('reporting_visualization', {})
        self.config = DashboardConfig(
            include_charts=plugin_config.get('include_charts', True),
            include_trends=plugin_config.get('include_trends', True),
            include_anomalies=plugin_config.get('include_anomalies', True),
            time_range_days=plugin_config.get('time_range_days', 30),
            refresh_interval_minutes=plugin_config.get('refresh_interval_minutes', 60),
            max_items_per_section=plugin_config.get('max_items_per_section', 50)
        )

        # Load built-in templates
        self._load_builtin_templates()

    def cleanup(self) -> None:
        """Clean up resources."""
        pass

    def export(self, data: Any, output_path: Path, **kwargs) -> None:
        """Export data to various formats."""
        format_type = kwargs.get('format', 'html')
        template_id = kwargs.get('template', 'default')

        if format_type == 'html':
            self._export_html(data, output_path, template_id, **kwargs)
        elif format_type == 'json':
            self._export_json(data, output_path, **kwargs)
        elif format_type == 'csv':
            self._export_csv(data, output_path, **kwargs)
        elif format_type == 'pdf':
            self._export_pdf(data, output_path, template_id, **kwargs)
        else:
            raise PluginError(f"Unsupported export format: {format_type}")

    def generate_dashboard_data(self, **kwargs) -> ReportData:
        """Generate comprehensive dashboard data."""
        time_range = kwargs.get('days', self.config.time_range_days)
        start_time = time.time() - (time_range * 24 * 60 * 60)

        # Gather data from various sources
        summary = self._generate_summary_stats(start_time)
        scans = self._get_recent_scans(start_time)
        anomalies = self._get_anomalies_data(start_time)
        trends = self._calculate_trends(start_time) if self.config.include_trends else {}
        recommendations = self._generate_recommendations(scans, anomalies)

        return ReportData(
            title=f"Khao2 Analysis Dashboard - Last {time_range} Days",
            summary=summary,
            scans=scans[:self.config.max_items_per_section],
            anomalies=anomalies[:self.config.max_items_per_section],
            trends=trends,
            recommendations=recommendations,
            generated_at=time.time()
        )

    def generate_executive_report(self, **kwargs) -> ReportData:
        """Generate executive-level summary report."""
        dashboard_data = self.generate_dashboard_data(**kwargs)

        # Focus on high-level metrics for executives
        executive_summary = {
            "total_scans": dashboard_data.summary.get("total_scans", 0),
            "suspicious_files": dashboard_data.summary.get("suspicious_files", 0),
            "risk_trend": dashboard_data.trends.get("risk_trend", "stable"),
            "top_risks": dashboard_data.anomalies[:5] if dashboard_data.anomalies else [],
            "key_recommendations": dashboard_data.recommendations[:3] if dashboard_data.recommendations else []
        }

        return ReportData(
            title="Executive Security Summary",
            summary=executive_summary,
            scans=[],  # Exclude detailed scans for executives
            anomalies=dashboard_data.anomalies[:10],
            trends=dashboard_data.trends,
            recommendations=dashboard_data.recommendations,
            generated_at=time.time(),
            metadata={"report_type": "executive"}
        )

    def _export_html(self, data: Any, output_path: Path,
                    template_id: str, **kwargs) -> None:
        """Export data as HTML report."""
        if isinstance(data, ReportData):
            report_data = data
        else:
            # Assume it's raw scan data, generate dashboard
            report_data = self.generate_dashboard_data(**kwargs)

        template = self.templates.get(template_id, self.templates.get('default'))
        if not template:
            raise PluginError(f"Template {template_id} not found")

        html_content = self._render_html_template(template, report_data)

        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)

    def _export_json(self, data: Any, output_path: Path, **kwargs) -> None:
        """Export data as JSON."""
        if isinstance(data, ReportData):
            json_data = {
                "title": data.title,
                "summary": data.summary,
                "scans": data.scans,
                "anomalies": data.anomalies,
                "trends": data.trends,
                "recommendations": data.recommendations,
                "generated_at": data.generated_at,
                "metadata": data.metadata
            }
        else:
            json_data = data

        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(json_data, f, indent=2, default=str)

    def _export_csv(self, data: Any, output_path: Path, **kwargs) -> None:
        """Export data as CSV."""
        import csv

        if isinstance(data, ReportData):
            # Export scans as CSV
            with open(output_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['Scan ID', 'File', 'Status', 'Verdict', 'Confidence', 'Anomalies', 'Timestamp'])

                for scan in data.scans:
                    writer.writerow([
                        scan.get('scan_id', ''),
                        scan.get('file_name', ''),
                        scan.get('status', ''),
                        scan.get('verdict', ''),
                        scan.get('confidence', ''),
                        len(scan.get('anomalies', [])),
                        scan.get('timestamp', '')
                    ])
        else:
            raise PluginError("CSV export requires ReportData object")

    def _export_pdf(self, data: Any, output_path: Path,
                   template_id: str, **kwargs) -> None:
        """Export data as PDF (requires additional dependencies)."""
        try:
            from reportlab.lib import colors
            from reportlab.lib.pagesizes import letter
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
            from reportlab.lib.styles import getSampleStyleSheet
        except ImportError as e:
            raise PluginError("PDF export requires reportlab: pip install reportlab") from e

        if not isinstance(data, ReportData):
            raise PluginError("PDF export requires ReportData object")

        doc = SimpleDocTemplate(str(output_path), pagesize=letter)
        styles = getSampleStyleSheet()
        story = []

        # Title
        story.append(Paragraph(data.title, styles['Title']))
        story.append(Spacer(1, 12))

        # Summary
        story.append(Paragraph("Summary", styles['Heading2']))
        summary_data = [[k, str(v)] for k, v in data.summary.items()]
        summary_table = Table(summary_data)
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 14),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(summary_table)
        story.append(Spacer(1, 12))

        # Recommendations
        if data.recommendations:
            story.append(Paragraph("Key Recommendations", styles['Heading2']))
            for rec in data.recommendations[:5]:
                story.append(Paragraph(f"• {rec.get('description', '')}", styles['Normal']))
            story.append(Spacer(1, 12))

        doc.build(story)

    def _render_html_template(self, template: ReportTemplate, data: ReportData) -> str:
        """Render HTML template with data."""
        html = template.template_data

        # Simple template substitution
        html = html.replace("{{title}}", data.title)
        html = html.replace("{{generated_at}}", time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(data.generated_at)))
        html = html.replace("{{summary}}", json.dumps(data.summary, indent=2))
        html = html.replace("{{scans_count}}", str(len(data.scans)))
        html = html.replace("{{anomalies_count}}", str(len(data.anomalies)))

        # Generate charts if enabled
        if self.config.include_charts:
            chart_html = self._generate_chart_html(data)
            html = html.replace("{{charts}}", chart_html)
        else:
            html = html.replace("{{charts}}", "")

        return html

    def _generate_chart_html(self, data: ReportData) -> str:
        """Generate HTML for charts using simple JavaScript."""
        chart_html = """
        <div class="chart-container">
            <h3>Scan Results Overview</h3>
            <canvas id="resultsChart" width="400" height="200"></canvas>
        </div>
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        <script>
            const ctx = document.getElementById('resultsChart').getContext('2d');
            const chart = new Chart(ctx, {
                type: 'doughnut',
                data: {
                    labels: ['Clean', 'Suspicious', 'Benign'],
                    datasets: [{
                        data: [/* Would populate with actual data */],
                        backgroundColor: ['#4CAF50', '#FF9800', '#2196F3']
                    }]
                }
            });
        </script>
        """
        return chart_html

    def _generate_summary_stats(self, start_time: float) -> Dict[str, Any]:
        """Generate summary statistics."""
        # This would integrate with actual data sources
        # For now, return mock data
        return {
            "total_scans": 150,
            "suspicious_files": 12,
            "clean_files": 138,
            "average_confidence": 0.85,
            "total_anomalies": 45,
            "processing_time_avg": 245.5
        }

    def _get_recent_scans(self, start_time: float) -> List[Dict[str, Any]]:
        """Get recent scans data."""
        # Mock data - would integrate with actual scan history
        return [
            {
                "scan_id": "scan_001",
                "file_name": "image1.png",
                "status": "completed",
                "verdict": "benign",
                "confidence": 0.92,
                "anomalies": [],
                "timestamp": time.time() - 3600
            }
        ]

    def _get_anomalies_data(self, start_time: float) -> List[Dict[str, Any]]:
        """Get anomalies data."""
        # Mock data
        return [
            {
                "id": "high_entropy",
                "description": "High entropy detected",
                "confidence": 0.8,
                "severity": "medium"
            }
        ]

    def _calculate_trends(self, start_time: float) -> Dict[str, Any]:
        """Calculate trend data."""
        return {
            "risk_trend": "decreasing",
            "scan_volume_trend": "increasing",
            "anomaly_trend": "stable"
        }

    def _generate_recommendations(self, scans: List[Dict[str, Any]],
                                anomalies: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Generate recommendations based on data."""
        recommendations = []

        suspicious_count = sum(1 for scan in scans if scan.get('verdict') == 'suspicious')
        if suspicious_count > 5:
            recommendations.append({
                "priority": "high",
                "description": "High number of suspicious files detected. Consider reviewing security policies."
            })

        if anomalies:
            recommendations.append({
                "priority": "medium",
                "description": "Anomalies detected. Review affected files with additional tools."
            })

        return recommendations

    def _load_builtin_templates(self) -> None:
        """Load built-in HTML templates."""
        default_template = ReportTemplate(
            template_id="default",
            name="Default Dashboard",
            description="Standard analysis dashboard",
            format="html",
            template_data="""
            <!DOCTYPE html>
            <html>
            <head>
                <title>{{title}}</title>
                <style>
                    body { font-family: Arial, sans-serif; margin: 20px; }
                    .header { background: #f0f0f0; padding: 20px; border-radius: 5px; }
                    .summary { background: #e8f4f8; padding: 15px; margin: 20px 0; border-radius: 5px; }
                    .chart-container { margin: 20px 0; }
                </style>
            </head>
            <body>
                <div class="header">
                    <h1>{{title}}</h1>
                    <p>Generated at: {{generated_at}}</p>
                </div>

                <div class="summary">
                    <h2>Summary</h2>
                    <p>Total Scans: {{scans_count}}</p>
                    <p>Anomalies Detected: {{anomalies_count}}</p>
                    <pre>{{summary}}</pre>
                </div>

                {{charts}}

                <div class="footer">
                    <p>Report generated by Khao2 Advanced Intelligence</p>
                </div>
            </body>
            </html>
            """,
            created_at=time.time()
        )

        self.templates["default"] = default_template


# Plugin metadata for discovery
PLUGIN_METADATA = ReportingVisualizationPlugin().metadata