import csv
import io
from xml.sax.saxutils import escape
from fastapi import APIRouter, Depends, Response
from fastapi.responses import StreamingResponse
from sqlalchemy import func
from sqlalchemy.orm import Session
from backend.app.database import get_db, SessionLocal
from backend.app.models import LogEvent, LogFile, ThreatAlert, User
from backend.app.api.auth import get_current_user
from backend.app.parsers.timeutil import utc_now

# ReportLab Imports for PDF Generation
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable, KeepTogether
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.pdfgen import canvas

router = APIRouter(prefix="/api/reports", tags=["Reports"])


# Spreadsheet apps treat a cell beginning with = + - @ (or a leading control
# character) as a formula, so a crafted log value could execute when the CSV is
# opened. Prefix any such value with an apostrophe to neutralise the injection.
_CSV_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def _csv_safe(value) -> str:
    text = "" if value is None else str(value)
    if text and text[0] in _CSV_FORMULA_PREFIXES:
        return "'" + text
    return text


class NumberedCanvas(canvas.Canvas):
    """Canvas that performs a two-pass render to dynamically draw total page count and footers."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            canvas.Canvas.showPage(self)
        canvas.Canvas.save(self)

    def draw_page_decorations(self, page_count):
        self.saveState()
        self.setFont("Helvetica", 8)
        self.setFillColor(colors.HexColor("#64748B"))
        
        # Header line & text on pages after cover/page 1
        self.setStrokeColor(colors.HexColor("#CBD5E1"))
        self.setLineWidth(0.5)
        self.line(36, 756, 576, 756)
        self.drawString(36, 762, "SecureSight AI — Executive SIEM Security Posture Report")
        self.drawRightString(576, 762, utc_now().strftime("%Y-%m-%d %H:%M UTC"))

        # Footer line & text
        self.line(36, 45, 576, 45)
        self.drawString(36, 32, "CONFIDENTIAL — FOR INTERNAL SECURITY TEAM USE ONLY")
        self.drawRightString(576, 32, f"Page {self._pageNumber} of {page_count}")
        self.restoreState()


@router.get("/alerts.csv")
def export_alerts_csv(current_user: User = Depends(get_current_user)):
    user_id = current_user.id

    def rows():
        # Own the session for the lifetime of the response iterator. Neither
        # database rows nor the generated CSV are accumulated in memory.
        with SessionLocal() as db:
            alerts_query = (db.query(ThreatAlert)
                            .join(LogEvent, ThreatAlert.log_event_id == LogEvent.id)
                            .join(LogFile, LogEvent.log_file_id == LogFile.id)
                            .filter(LogFile.user_id == user_id)
                            .order_by(ThreatAlert.timestamp.desc()))
            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow(["id", "threat_type", "severity", "source_ip", "risk_score", "confidence", "status", "timestamp", "evidence"])
            yield output.getvalue()
            output.seek(0)
            output.truncate(0)
            for index, alert in enumerate(alerts_query.yield_per(1000), start=1):
                writer.writerow([
                    alert.id,
                    _csv_safe(alert.threat_type),
                    _csv_safe(alert.severity),
                    _csv_safe(alert.source_ip or ""),
                    alert.risk_score,
                    alert.confidence,
                    _csv_safe(alert.status),
                    alert.timestamp.isoformat() if alert.timestamp else "",
                    _csv_safe(alert.evidence or ""),
                ])
                if index % 1000 == 0:
                    yield output.getvalue()
                    output.seek(0)
                    output.truncate(0)
            if output.tell():
                yield output.getvalue()

    return StreamingResponse(
        rows(),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=securesight-alerts.csv"}
    )


@router.get("/pdf")
def export_security_report_pdf(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    # 1. Fetch user data — counts and bounded result sets only, so large
    #    datasets (hundreds of thousands of events) do not get materialized.
    files = db.query(LogFile).filter(LogFile.user_id == current_user.id).limit(100).all()
    total_events = (
        db.query(func.count(LogEvent.id))
        .join(LogFile, LogEvent.log_file_id == LogFile.id)
        .filter(LogFile.user_id == current_user.id)
        .scalar() or 0
    )
    alerts_base = (
        db.query(ThreatAlert)
        .join(LogEvent, ThreatAlert.log_event_id == LogEvent.id)
        .join(LogFile, LogEvent.log_file_id == LogFile.id)
        .filter(LogFile.user_id == current_user.id)
    )
    severity_counts = dict(
        alerts_base.with_entities(ThreatAlert.severity, func.count(ThreatAlert.id))
        .group_by(ThreatAlert.severity)
        .all()
    )
    status_counts = dict(
        alerts_base.with_entities(ThreatAlert.status, func.count(ThreatAlert.id))
        .group_by(ThreatAlert.status)
        .all()
    )
    top_ip_counts = {
        ip: count
        for ip, count in alerts_base.with_entities(ThreatAlert.source_ip, func.count(ThreatAlert.id))
        .filter(ThreatAlert.source_ip != None)  # noqa: E711
        .group_by(ThreatAlert.source_ip)
        .order_by(func.count(ThreatAlert.id).desc())
        .limit(5)
        .all()
    }
    max_risk = alerts_base.with_entities(func.max(ThreatAlert.risk_score)).scalar() or 0
    alerts = alerts_base.order_by(ThreatAlert.timestamp.desc()).limit(25).all()

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        leftMargin=36,
        rightMargin=36,
        topMargin=54,
        bottomMargin=54
    )

    styles = getSampleStyleSheet()
    
    # Custom styles
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=20,
        leading=24,
        textColor=colors.HexColor('#0F172A')
    )
    h2_style = ParagraphStyle(
        'Heading2_Custom',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=13,
        leading=16,
        textColor=colors.HexColor('#1E293B'),
        spaceBefore=12,
        spaceAfter=6
    )
    body_style = ParagraphStyle(
        'Body_Custom',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9,
        leading=12,
        textColor=colors.HexColor('#334155')
    )
    table_header_style = ParagraphStyle(
        'TableHeader',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=8,
        leading=10,
        textColor=colors.HexColor('#FFFFFF')
    )
    table_cell_style = ParagraphStyle(
        'TableCell',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8,
        leading=10,
        textColor=colors.HexColor('#1E293B')
    )
    table_cell_mono = ParagraphStyle(
        'TableCellMono',
        parent=styles['Normal'],
        fontName='Courier',
        fontSize=8,
        leading=10,
        textColor=colors.HexColor('#0F172A')
    )

    story = []

    # ── Report Header Title Box ──────────────────────────────────────────────
    header_data = [
        [
            Paragraph("SECURESIGHT AI", ParagraphStyle('LogoText', fontName='Helvetica-Bold', fontSize=14, leading=16, textColor=colors.HexColor('#7C3AED'))),
            Paragraph(f"<b>Analyst:</b> {escape(current_user.full_name)}<br/><b>Email:</b> {escape(current_user.email)}", ParagraphStyle('RightHeader', fontName='Helvetica', fontSize=8, leading=10, alignment=2, textColor=colors.HexColor('#475569')))
        ],
        [
            Paragraph("Security Posture & SIEM Incident Audit Report", title_style),
            Paragraph(f"<b>Generated:</b> {utc_now().strftime('%b %d, %Y %H:%M UTC')}<br/><b>Status:</b> Official Audit", ParagraphStyle('RightSubHeader', fontName='Helvetica', fontSize=8, leading=10, alignment=2, textColor=colors.HexColor('#475569')))
        ]
    ]
    header_table = Table(header_data, colWidths=[340, 200])
    header_table.setStyle(TableStyle([
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('BOTTOMPADDING', (0,0), (-1,-1), 2),
        ('TOPPADDING', (0,0), (-1,-1), 2),
    ]))
    story.append(header_table)
    story.append(Spacer(1, 8))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor('#7C3AED'), spaceBefore=2, spaceAfter=10))

    # ── Metric KPI Grid ─────────────────────────────────────────────────────
    total_threats = sum(severity_counts.values())
    active_threats = status_counts.get('active', 0)
    total_files = len(files)

    kpi_data = [
        [
            Paragraph(f"<b>TOTAL LOG EVENTS</b><br/><font size=14 color='#0F172A'><b>{total_events:,}</b></font>", body_style),
            Paragraph(f"<b>THREATS DETECTED</b><br/><font size=14 color='#EF4444'><b>{total_threats}</b></font>", body_style),
            Paragraph(f"<b>ACTIVE INCIDENTS</b><br/><font size=14 color='#F59E0B'><b>{active_threats}</b></font>", body_style),
            Paragraph(f"<b>MAX RISK SCORE</b><br/><font size=14 color='#7C3AED'><b>{max_risk}/100</b></font>", body_style),
        ]
    ]
    kpi_table = Table(kpi_data, colWidths=[135, 135, 135, 135])
    kpi_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#F8FAFC')),
        ('BOX', (0,0), (-1,-1), 1, colors.HexColor('#E2E8F0')),
        ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor('#E2E8F0')),
        ('PADDING', (0,0), (-1,-1), 8),
        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
    ]))
    story.append(kpi_table)
    story.append(Spacer(1, 14))

    # ── Executive Summary ───────────────────────────────────────────────────
    story.append(Paragraph("1. Executive Security Summary", h2_style))
    summary_text = (
        f"This report presents an automated SIEM security audit for workspace owner <b>{escape(current_user.full_name)}</b>. "
        f"A total of <b>{total_files} log file(s)</b> containing <b>{total_events:,} raw log records</b> were parsed and analyzed. "
        f"Our correlation and signature engine flagged <b>{total_threats} security incidents</b>, of which <b>{active_threats} remain active</b> requiring triage. "
        f"The peak risk score evaluated across all incidents is <b>{max_risk}/100</b>."
    )
    story.append(Paragraph(summary_text, body_style))
    story.append(Spacer(1, 10))

    # ── Severity & Attack Breakdown ─────────────────────────────────────────
    story.append(Paragraph("2. Threat Classification & Severity Distribution", h2_style))
    
    crit_count = severity_counts.get('CRITICAL', 0)
    high_count = severity_counts.get('HIGH', 0)
    med_count = severity_counts.get('MEDIUM', 0)
    low_count = severity_counts.get('LOW', 0)

    sev_data = [
        [
            Paragraph("Severity Level", table_header_style),
            Paragraph("Alert Count", table_header_style),
            Paragraph("Percentage", table_header_style),
            Paragraph("Action Level", table_header_style)
        ],
        [Paragraph("<font color='#EF4444'><b>CRITICAL</b></font>", table_cell_style), Paragraph(str(crit_count), table_cell_style), Paragraph(f"{(crit_count/total_threats*100):.1f}%" if total_threats else "0%", table_cell_style), Paragraph("Immediate Incident Isolation", table_cell_style)],
        [Paragraph("<font color='#F97316'><b>HIGH</b></font>", table_cell_style), Paragraph(str(high_count), table_cell_style), Paragraph(f"{(high_count/total_threats*100):.1f}%" if total_threats else "0%", table_cell_style), Paragraph("Urgent Remediation", table_cell_style)],
        [Paragraph("<font color='#F59E0B'><b>MEDIUM</b></font>", table_cell_style), Paragraph(str(med_count), table_cell_style), Paragraph(f"{(med_count/total_threats*100):.1f}%" if total_threats else "0%", table_cell_style), Paragraph("Scheduled Investigation", table_cell_style)],
        [Paragraph("<font color='#3B82F6'><b>LOW</b></font>", table_cell_style), Paragraph(str(low_count), table_cell_style), Paragraph(f"{(low_count/total_threats*100):.1f}%" if total_threats else "0%", table_cell_style), Paragraph("Routine Monitoring", table_cell_style)],
    ]
    sev_table = Table(sev_data, colWidths=[120, 100, 100, 220])
    sev_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1E293B')),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#CBD5E1')),
        ('PADDING', (0,0), (-1,-1), 5),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#F8FAFC')])
    ]))
    story.append(sev_table)
    story.append(Spacer(1, 12))

    # ── Top Attacker Source IPs ─────────────────────────────────────────────
    story.append(Paragraph("3. Top Suspicious Remote Source IPs", h2_style))
    top_ips = top_ip_counts.items()

    if top_ips:
        ip_table_data = [
            [Paragraph("Rank", table_header_style), Paragraph("Attacker IP Address", table_header_style), Paragraph("Alert Count", table_header_style), Paragraph("Threat Assessment", table_header_style)]
        ]
        for rank, (ip, count) in enumerate(top_ips, 1):
            ip_table_data.append([
                Paragraph(f"#{rank}", table_cell_style),
                Paragraph(escape(ip), table_cell_mono),
                Paragraph(str(count), table_cell_style),
                Paragraph("High frequency attack source — perimeter block advised", table_cell_style)
            ])
        ip_table = Table(ip_table_data, colWidths=[50, 150, 90, 250])
        ip_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#0F172A')),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#CBD5E1')),
            ('PADDING', (0,0), (-1,-1), 5),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#F8FAFC')])
        ]))
        story.append(ip_table)
    else:
        story.append(Paragraph("No IP addresses were associated with security alerts.", body_style))
    story.append(Spacer(1, 14))

    # ── Detailed Incident Table ────────────────────────────────────────────
    story.append(Paragraph("4. Detailed Incident Registry", h2_style))
    if alerts:
        alert_data = [
            [
                Paragraph("ID", table_header_style),
                Paragraph("Threat Type", table_header_style),
                Paragraph("Sev", table_header_style),
                Paragraph("Source IP", table_header_style),
                Paragraph("Risk", table_header_style),
                Paragraph("Status", table_header_style),
                Paragraph("Timestamp", table_header_style)
            ]
        ]
        for a in alerts[:25]:  # Include up to 25 detailed records
            sev_color = "#EF4444" if a.severity == "CRITICAL" else "#F97316" if a.severity == "HIGH" else "#F59E0B" if a.severity == "MEDIUM" else "#3B82F6"
            alert_data.append([
                Paragraph(str(a.id), table_cell_mono),
                Paragraph(escape(a.threat_type), table_cell_style),
                Paragraph(f"<font color='{sev_color}'><b>{a.severity}</b></font>", table_cell_style),
                Paragraph(escape(a.source_ip or "N/A"), table_cell_mono),
                Paragraph(f"{a.risk_score}/100", table_cell_style),
                Paragraph(a.status.upper(), table_cell_style),
                Paragraph(a.timestamp.strftime("%Y-%m-%d %H:%M") if a.timestamp else "N/A", table_cell_style)
            ])
        alert_table = Table(alert_data, colWidths=[30, 140, 55, 95, 45, 65, 110])
        alert_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1E293B')),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#CBD5E1')),
            ('PADDING', (0,0), (-1,-1), 4),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#F8FAFC')])
        ]))
        story.append(alert_table)
    else:
        story.append(Paragraph("No detailed incident records found.", body_style))

    story.append(Spacer(1, 14))

    # ── Security Recommendations ────────────────────────────────────────────
    story.append(KeepTogether([
        Paragraph("5. Recommended Security Countermeasures", h2_style),
        Paragraph("1. <b>Firewall IP Containment:</b> Add top attacker IPs identified in Section 3 to drop rules at your boundary firewall/WAF.", body_style),
        Paragraph("2. <b>SSH Hardening:</b> Enforce public-key authentication only and deploy <code>fail2ban</code> to automatically block brute-force attempts.", body_style),
        Paragraph("3. <b>Web Application Defense:</b> Enforce strict parameterized SQL queries and input sanitization to eliminate SQLi & XSS vectors.", body_style),
        Paragraph("4. <b>Continuous Monitoring:</b> Regularly ingest application and server logs into SecureSight AI for automated correlation.", body_style),
    ]))

    # Build document with custom page canvas
    doc.build(story, canvasmaker=NumberedCanvas)
    
    buffer.seek(0)
    pdf_bytes = buffer.getvalue()

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f"attachment; filename=securesight-report-{utc_now().strftime('%Y%m%d')}.pdf"
        }
    )
