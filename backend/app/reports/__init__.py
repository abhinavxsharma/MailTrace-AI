"""
MAILTRACE AI - Forensic Report Generation Package.
Exposes report builder, JSON serializer, and ReportLab PDF generator.
"""

from app.reports.report_builder import build_case_report, generate_forensic_conclusion
from app.reports.json_report import generate_json_report
from app.reports.pdf_report import generate_pdf_report

__all__ = [
    "build_case_report",
    "generate_forensic_conclusion",
    "generate_json_report",
    "generate_pdf_report",
]
