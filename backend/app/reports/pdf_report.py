"""
MAILTRACE AI - Professional PDF Forensic Case Report Generator.
Uses ReportLab to produce courtroom-ready, structured forensic investigation documentation.
"""

from io import BytesIO
from pathlib import Path
from typing import Any, Dict, List, Optional

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import (
    HRFlowable,
    KeepTogether,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)


def _get_level_color(level: str) -> colors.HexColor:
    lvl = (level or "").upper()
    if "CRIT" in lvl:
        return colors.HexColor("#dc2626")  # Red
    if "HIGH" in lvl:
        return colors.HexColor("#ea580c")  # Orange
    if "MED" in lvl:
        return colors.HexColor("#d97706")  # Amber
    return colors.HexColor("#16a34a")      # Green


class NumberedCanvas:
    """Two-pass canvas to dynamically compute and draw total page numbers and headers."""

    def __init__(self, *args: Any, **kwargs: Any):
        super().__init__(*args, **kwargs)
        self._saved_page_states: List[Any] = []

    def showPage(self) -> None:
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self) -> None:
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, page_count: int) -> None:
        self.saveState()
        self.setFont("Helvetica", 8)
        self.setFillColor(colors.HexColor("#64748b"))

        # Running Header (pages > 1)
        if self._pageNumber > 1:
            self.drawString(36, 762, "MAILTRACE AI — FORENSIC INVESTIGATION REPORT")
            self.drawRightString(576, 762, "CONFIDENTIAL / CHAIN OF CUSTODY")
            self.setStrokeColor(colors.HexColor("#cbd5e1"))
            self.setLineWidth(0.5)
            self.line(36, 756, 576, 756)

        # Running Footer (all pages)
        self.setStrokeColor(colors.HexColor("#cbd5e1"))
        self.setLineWidth(0.5)
        self.line(36, 42, 576, 42)
        self.drawString(36, 30, "PRODUCED BY MAILTRACE AI PLATFORM • IMMUTABLE EVIDENCE ARTIFACT")
        page_str = f"Page {self._pageNumber} of {page_count}"
        self.drawRightString(576, 30, page_str)
        self.restoreState()


def generate_pdf_report(
    report_data: Dict[str, Any],
    output_path: Optional[Path] = None,
) -> bytes:
    """
    Generate professional downloadable PDF report matching Phase 9 specifications.
    """
    from reportlab.pdfgen import canvas

    class CustomCanvas(NumberedCanvas, canvas.Canvas):
        pass

    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        leftMargin=36,
        rightMargin=36,
        topMargin=44,
        bottomMargin=50,
    )

    styles = getSampleStyleSheet()

    # Custom typography styles
    title_style = ParagraphStyle(
        "DocTitle",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=20,
        leading=24,
        textColor=colors.HexColor("#0f172a"),
    )
    subtitle_style = ParagraphStyle(
        "DocSubtitle",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=12,
        textColor=colors.HexColor("#64748b"),
    )
    h1_style = ParagraphStyle(
        "SectionHeading",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=12,
        leading=16,
        textColor=colors.HexColor("#0f172a"),
        spaceBefore=12,
        spaceAfter=6,
    )
    body_style = ParagraphStyle(
        "Body",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=13,
        textColor=colors.HexColor("#334155"),
    )
    bold_body = ParagraphStyle(
        "BoldBody",
        parent=body_style,
        fontName="Helvetica-Bold",
        textColor=colors.HexColor("#0f172a"),
    )
    mono_style = ParagraphStyle(
        "Mono",
        parent=styles["Normal"],
        fontName="Courier",
        fontSize=8,
        leading=11,
        textColor=colors.HexColor("#1e293b"),
    )
    callout_style = ParagraphStyle(
        "Callout",
        parent=styles["Normal"],
        fontName="Helvetica-Oblique",
        fontSize=8.5,
        leading=12,
        textColor=colors.HexColor("#475569"),
    )

    story: List[Any] = []

    case_id = report_data.get("case_id", "UNKNOWN")
    case_status = report_data.get("case_status", "ANALYZED")
    risk = report_data.get("risk", {})
    risk_score = risk.get("score", 0)
    risk_level = risk.get("level", "LOW")
    level_color = _get_level_color(risk_level)
    evidence = report_data.get("evidence", {})
    email_dict = report_data.get("email", {})
    ai = report_data.get("ai", {})
    features = report_data.get("features", {})
    auth = report_data.get("authentication", {})
    infra = report_data.get("infrastructure", {})
    graph = report_data.get("graph", {})
    corr = report_data.get("correlation", {})
    timeline = report_data.get("timeline", [])

    # -------------------------------------------------------------
    # HEADER / TITLE BLOCK
    # -------------------------------------------------------------
    header_data = [
        [
            Paragraph("<b>MAILTRACE AI</b>", title_style),
            Paragraph(f"<b>CASE: {case_id}</b>", ParagraphStyle("RCase", parent=title_style, alignment=2, fontSize=14)),
        ],
        [
            Paragraph("Forensic Email Threat Investigation Report", subtitle_style),
            Paragraph(f"Status: <b>{case_status}</b> • Generated: {report_data.get('generation_timestamp', '')[:19].replace('T', ' ')} UTC", ParagraphStyle("RMeta", parent=subtitle_style, alignment=2)),
        ],
    ]
    header_table = Table(header_data, colWidths=[320, 220])
    header_table.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 1),
        ("TOPPADDING", (0, 0), (-1, -1), 1),
    ]))
    story.append(header_table)
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#0f172a"), spaceAfter=10, spaceBefore=6))

    # -------------------------------------------------------------
    # EXECUTIVE VERDICT & SCORE BANNER
    # -------------------------------------------------------------
    score_data = [
        [
            Paragraph(
                f"<font size=10 color='#64748b'>RISK CLASSIFICATION</font><br/>"
                f"<font size=18 color='{level_color.hexval()}'><b>{risk_level} RISK</b></font><br/>"
                f"<font size=8.5 color='#475569'>AI Model: {ai.get('model')} • Verdict: <b>{ai.get('classification')}</b> ({ai.get('confidence', 0.0):.1%} conf)</font>",
                body_style,
            ),
            Paragraph(
                f"<font size=10 color='#64748b'>COMPOSITE SCORE</font><br/>"
                f"<font size=28 color='{level_color.hexval()}'><b>{risk_score}</b></font><font size=14 color='#94a3b8'>/100</font>",
                ParagraphStyle("RScore", parent=body_style, alignment=2),
            ),
        ]
    ]
    score_table = Table(score_data, colWidths=[400, 140])
    score_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
        ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#cbd5e1")),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("LEFTPADDING", (0, 0), (-1, -1), 12),
        ("RIGHTPADDING", (0, 0), (-1, -1), 12),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    story.append(score_table)
    story.append(Spacer(1, 10))

    # -------------------------------------------------------------
    # SECTION 1: CASE OVERVIEW & CONCLUSION
    # -------------------------------------------------------------
    story.append(Paragraph("1. Executive Summary & Forensic Conclusion", h1_style))
    conclusion_text = report_data.get("conclusion", "Forensic analysis completed.")
    story.append(Paragraph(conclusion_text, body_style))
    story.append(Spacer(1, 8))

    # -------------------------------------------------------------
    # SECTION 2: ORIGINAL EMAIL METADATA
    # -------------------------------------------------------------
    story.append(Paragraph("2. Original Email Details", h1_style))
    email_rows = [
        [Paragraph("<b>Subject:</b>", body_style), Paragraph(email_dict.get("subject") or "Untitled", bold_body)],
        [Paragraph("<b>From:</b>", body_style), Paragraph(email_dict.get("from") or "None", mono_style)],
        [Paragraph("<b>To:</b>", body_style), Paragraph(email_dict.get("to") or "None", mono_style)],
        [Paragraph("<b>Reply-To:</b>", body_style), Paragraph(email_dict.get("reply_to") or "None", mono_style)],
        [Paragraph("<b>Return-Path:</b>", body_style), Paragraph(email_dict.get("return_path") or "None", mono_style)],
        [Paragraph("<b>Date Header:</b>", body_style), Paragraph(email_dict.get("date") or "None", body_style)],
        [Paragraph("<b>Message-ID:</b>", body_style), Paragraph(email_dict.get("message_id") or "None", mono_style)],
    ]
    email_table = Table(email_rows, colWidths=[90, 450])
    email_table.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LINEBELOW", (0, 0), (-1, -1), 0.5, colors.HexColor("#f1f5f9")),
        ("TOPPADDING", (0, 0), (-1, -1), 2.5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5),
    ]))
    story.append(email_table)
    story.append(Spacer(1, 8))

    # -------------------------------------------------------------
    # SECTION 3: EVIDENCE PRESERVATION (CHAIN OF CUSTODY)
    # -------------------------------------------------------------
    story.append(Paragraph("3. Evidence Chain of Custody & Fingerprint", h1_style))
    evidence_rows = [
        [Paragraph("<b>Artifact File:</b>", body_style), Paragraph(f"{evidence.get('original_filename')} ({evidence.get('file_size', 0):,} bytes)", body_style)],
        [Paragraph("<b>SHA-256 Fingerprint:</b>", body_style), Paragraph(f"<b>{evidence.get('sha256')}</b>", mono_style)],
        [Paragraph("<b>Custody Status:</b>", body_style), Paragraph("SECURED & IMMUTABLE (Preserved at initial ingestion)", body_style)],
    ]
    ev_table = Table(evidence_rows, colWidths=[120, 420])
    ev_table.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LINEBELOW", (0, 0), (-1, -1), 0.5, colors.HexColor("#f1f5f9")),
        ("TOPPADDING", (0, 0), (-1, -1), 2.5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5),
    ]))
    story.append(ev_table)
    story.append(Spacer(1, 8))

    # -------------------------------------------------------------
    # SECTION 4: AUTHENTICATION & IDENTITY CONSISTENCY
    # -------------------------------------------------------------
    story.append(Paragraph("4. Authentication & Identity Consistency", h1_style))
    auth_rows = [
        [
            Paragraph(f"<b>SPF:</b> {auth.get('spf')}", body_style),
            Paragraph(f"<b>DKIM:</b> {auth.get('dkim')}", body_style),
            Paragraph(f"<b>DMARC:</b> {auth.get('dmarc')}", body_style),
            Paragraph(f"<b>Overall Alignment:</b> <b>{auth.get('overall_alignment')}</b>", body_style),
        ],
        [
            Paragraph(f"<b>Reply-To Mismatch:</b> {'YES' if features.get('reply_to_mismatch') else 'NO'}", body_style),
            Paragraph(f"<b>Return-Path Mismatch:</b> {'YES' if features.get('return_path_mismatch') else 'NO'}", body_style),
            Paragraph(f"<b>Observed Source IP:</b> {infra.get('source_ip')}", body_style),
            Paragraph("", body_style),
        ],
    ]
    auth_table = Table(auth_rows, colWidths=[135, 135, 135, 135])
    auth_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
        ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#e2e8f0")),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(auth_table)
    story.append(Spacer(1, 8))

    # -------------------------------------------------------------
    # SECTION 5: AI THREAT DETECTION & FORENSIC FEATURES
    # -------------------------------------------------------------
    story.append(Paragraph("5. AI Sequence Classification & Linguistic Signals", h1_style))
    ai_feat_text = (
        f"<b>DistilBERT Threat Classification:</b> {ai.get('classification')} (Confidence: {ai.get('confidence', 0.0):.1%})<br/>"
        f"<b>Detected Behavioral Features:</b> "
        f"Urgency: {'DETECTED' if features.get('urgency') else 'NO'} | "
        f"Financial/Wire: {'DETECTED' if features.get('financial') else 'NO'} | "
        f"Authority Coercion: {'DETECTED' if features.get('authority') else 'NO'} | "
        f"Secrecy Pressure: {'DETECTED' if features.get('secrecy') else 'NO'} | "
        f"Credential Harvesting: {'DETECTED' if features.get('credentials') else 'NO'} | "
        f"Suspicious Portal Links: {'DETECTED' if features.get('suspicious_links') else 'NO'}"
    )
    story.append(Paragraph(ai_feat_text, body_style))
    story.append(Spacer(1, 8))

    # -------------------------------------------------------------
    # SECTION 6: INFRASTRUCTURE INTELLIGENCE
    # -------------------------------------------------------------
    story.append(Paragraph("6. Observed Source Infrastructure & IP Geolocation", h1_style))
    city_val = infra.get('city')
    city_suffix = f" ({city_val})" if city_val and city_val != 'Unavailable' else ""
    geo_display = f"{infra.get('country') or 'Unavailable'}{city_suffix}"

    infra_rows = [
        [Paragraph("<b>Source IP:</b>", body_style), Paragraph(str(infra.get("source_ip")), mono_style)],
        [Paragraph("<b>RDAP Network:</b>", body_style), Paragraph(f"{infra.get('organization')} ({infra.get('network_name')})", body_style)],
        [Paragraph("<b>IP Geolocation:</b>", body_style), Paragraph(geo_display, body_style)],
        [Paragraph("<b>Reverse DNS:</b>", body_style), Paragraph(str(infra.get("reverse_dns")), mono_style)],
    ]
    infra_table = Table(infra_rows, colWidths=[120, 420])
    infra_table.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LINEBELOW", (0, 0), (-1, -1), 0.5, colors.HexColor("#f1f5f9")),
        ("TOPPADDING", (0, 0), (-1, -1), 2),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
    ]))
    story.append(infra_table)
    story.append(Spacer(1, 8))

    # -------------------------------------------------------------
    # SECTION 7: RISK BREAKDOWN (6 DIMENSIONS)
    # -------------------------------------------------------------
    story.append(Paragraph("7. Explainable Evidence Fusion Breakdown", h1_style))
    contribs = risk.get("contributions", {})
    risk_dim_rows = [
        [
            Paragraph("<b>Dimension</b>", bold_body),
            Paragraph("<b>Points Contributed</b>", bold_body),
            Paragraph("<b>Category Max</b>", bold_body),
            Paragraph("<b>Status / Factor</b>", bold_body),
        ],
        [Paragraph("AI Threat Detection", body_style), Paragraph(str(contribs.get("ai_threat", 0)), mono_style), Paragraph("25", mono_style), Paragraph(str(ai.get("classification")), body_style)],
        [Paragraph("Identity Consistency", body_style), Paragraph(str(contribs.get("identity", 0)), mono_style), Paragraph("20", mono_style), Paragraph("From vs Reply-To / Return-Path", body_style)],
        [Paragraph("Authentication Alignment", body_style), Paragraph(str(contribs.get("authentication", 0)), mono_style), Paragraph("15", mono_style), Paragraph(f"DMARC {auth.get('dmarc')}", body_style)],
        [Paragraph("URL & Domain Signals", body_style), Paragraph(str(contribs.get("url_domain", 0)), mono_style), Paragraph("15", mono_style), Paragraph(f"{features.get('url_count', 0)} URL(s) detected", body_style)],
        [Paragraph("Infrastructure Intelligence", body_style), Paragraph(str(contribs.get("infrastructure", 0)), mono_style), Paragraph("15", mono_style), Paragraph(f"Host {infra.get('source_ip')}", body_style)],
        [Paragraph("Campaign Correlation", body_style), Paragraph(str(contribs.get("campaign", 0)), mono_style), Paragraph("10", mono_style), Paragraph(f"{len(corr.get('related_cases', []))} related case(s)", body_style)],
        [Paragraph("<b>TOTAL RISK SCORE</b>", bold_body), Paragraph(f"<b>{risk_score}</b>", ParagraphStyle("BScore", parent=mono_style, textColor=level_color, fontSize=10)), Paragraph("<b>100</b>", mono_style), Paragraph(f"<b>{risk_level}</b>", bold_body)],
    ]
    dim_table = Table(risk_dim_rows, colWidths=[180, 100, 90, 170])
    dim_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
        ("BACKGROUND", (0, -1), (-1, -1), colors.HexColor("#f8fafc")),
        ("LINEBELOW", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#cbd5e1")),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    story.append(dim_table)
    story.append(Spacer(1, 8))

    # -------------------------------------------------------------
    # SECTION 8 & 9: GRAPH & CAMPAIGN CORRELATION
    # -------------------------------------------------------------
    story.append(Paragraph("8. Relationship Graph & Campaign Correlation", h1_style))
    related_ids = corr.get("related_cases", [])
    graph_text = (
        f"<b>Forensic Graph:</b> NetworkX knowledge graph constructed with <b>{graph.get('node_count', 0)} nodes</b> "
        f"and <b>{graph.get('edge_count', 0)} edges</b>.<br/>"
        f"<b>Potential Campaign Relationship:</b> {corr.get('relationship_strength', 'NONE')} strength "
        f"(Campaign Score: {corr.get('campaign_score', 0)}/10).<br/>"
        f"<b>Related Case Identifiers:</b> {', '.join(related_ids) if related_ids else 'None (Isolated case)'}."
    )
    story.append(Paragraph(graph_text, body_style))

    # Correlation reasons if any
    reasons = corr.get("correlation_reasons", [])
    if reasons:
        story.append(Spacer(1, 4))
        for r_stmt in reasons:
            story.append(Paragraph(f"• {r_stmt}", callout_style))
    story.append(Spacer(1, 8))

    # -------------------------------------------------------------
    # SECTION 10: FORENSIC TIMELINE
    # -------------------------------------------------------------
    story.append(Paragraph("9. Chronological Forensic Timeline", h1_style))
    if timeline:
        time_rows = [[Paragraph("<b>Timestamp (UTC)</b>", bold_body), Paragraph("<b>Event</b>", bold_body), Paragraph("<b>Source / Details</b>", bold_body)]]
        for item in timeline[:8]:  # show top 8 events
            ts_str = str(item.get("timestamp", ""))[:19].replace("T", " ")
            ev_str = str(item.get("event", "")).replace("_", " ")
            det_str = f"[{item.get('source')}] {item.get('details', '')}"
            time_rows.append([Paragraph(ts_str, mono_style), Paragraph(ev_str, body_style), Paragraph(det_str, body_style)])

        time_table = Table(time_rows, colWidths=[120, 130, 290])
        time_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
            ("LINEBELOW", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ("TOPPADDING", (0, 0), (-1, -1), 2),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        story.append(time_table)
    else:
        story.append(Paragraph("No chronological timeline recorded.", body_style))
    story.append(Spacer(1, 10))

    # -------------------------------------------------------------
    # SECTION 11: FORENSIC SAFETY & DISCLAIMERS
    # -------------------------------------------------------------
    story.append(KeepTogether([
        HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#cbd5e1"), spaceAfter=6, spaceBefore=4),
        Paragraph("<b>10. Forensic Safeguard Notice & Methodological Disclaimers</b>", ParagraphStyle("DiscHead", parent=styles["Normal"], fontName="Helvetica-Bold", fontSize=8, textColor=colors.HexColor("#475569"))),
        Paragraph(
            report_data.get("forensic_disclaimer")
            or "Observed source infrastructure indicates network routing artifacts and registry allocations. IP Geolocation is approximate and does not prove human identity or exact physical location.",
            ParagraphStyle("DiscBody", parent=styles["Normal"], fontName="Helvetica", fontSize=7.5, leading=10, textColor=colors.HexColor("#64748b")),
        ),
    ]))

    # Build PDF using NumberedCanvas
    doc.build(story, canvasmaker=CustomCanvas)

    pdf_bytes = buffer.getvalue()
    buffer.close()

    if output_path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_bytes(pdf_bytes)

    return pdf_bytes
