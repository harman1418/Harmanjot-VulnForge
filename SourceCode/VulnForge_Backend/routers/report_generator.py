# VulnForge Professional Report Generator
# Import this in fullscan.py: from routers.report_generator import generate_report

def generate_report(target, scan_results, ai_analysis, attack_results, scan_type="medium"):
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import cm, mm
    from reportlab.lib import colors
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        HRFlowable, PageBreak, KeepTogether
    )
    from reportlab.lib.enums import TA_CENTER, TA_RIGHT, TA_LEFT
    from reportlab.platypus import BaseDocTemplate, Frame, PageTemplate
    from reportlab.lib.units import inch

    import re
    def clean_ansi_recursive(data):
        if isinstance(data, str):
            # regex to strip ANSI escape sequences
            ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
            cleaned = ansi_escape.sub('', data)
            # Also strip literal raw ANSI codes that got converted to plain text (like [1;94m or [0m)
            cleaned = re.sub(r'\[\d+(?:;\d+)*[mGKH]', '', cleaned)
            # Strip literal non-ascii marker block chars (like ■)
            cleaned = cleaned.replace('■', '')
            return cleaned.strip()
        elif isinstance(data, dict):
            return {k: clean_ansi_recursive(v) for k, v in data.items()}
        elif isinstance(data, list):
            return [clean_ansi_recursive(x) for x in data]
        return data

    scan_results = clean_ansi_recursive(scan_results)
    ai_analysis = clean_ansi_recursive(ai_analysis)
    if attack_results:
        attack_results = clean_ansi_recursive(attack_results)

    # ── Color Palette (Professional White Theme) ──────────────────────────────
    C_BG        = colors.white
    C_DARK      = colors.HexColor('#111827')
    C_GRAY      = colors.HexColor('#6B7280')
    C_LT_GRAY   = colors.HexColor('#F9FAFB')
    C_BORDER    = colors.HexColor('#E5E7EB')
    C_MED_GRAY  = colors.HexColor('#374151')

    C_GREEN     = colors.HexColor('#059669')
    C_GREEN_BG  = colors.HexColor('#ECFDF5')
    C_GREEN_BD  = colors.HexColor('#A7F3D0')

    C_RED       = colors.HexColor('#DC2626')
    C_RED_BG    = colors.HexColor('#FEF2F2')
    C_RED_BD    = colors.HexColor('#FECACA')

    C_ORANGE    = colors.HexColor('#D97706')
    C_ORANGE_BG = colors.HexColor('#FFFBEB')
    C_ORANGE_BD = colors.HexColor('#FDE68A')

    C_YELLOW    = colors.HexColor('#B45309')
    C_YELLOW_BG = colors.HexColor('#FEFCE8')

    C_BLUE      = colors.HexColor('#2563EB')
    C_BLUE_BG   = colors.HexColor('#EFF6FF')
    C_BLUE_BD   = colors.HexColor('#BFDBFE')

    C_ACCENT    = colors.HexColor('#00875A')  # VulnForge green
    C_HEADER_BG = colors.HexColor('#1E293B')  # Dark navy for header

    risk = ai_analysis.get("risk_level", "UNKNOWN")
    scan_label = {"light": "Light Scan", "medium": "Medium Scan", "deep": "Deep Scan"}.get(scan_type, "Scan")

    def risk_color(r):
        r = (r or "").upper()
        if r == "CRITICAL": return C_RED
        if r == "HIGH":     return C_ORANGE
        if r == "MEDIUM":   return C_YELLOW
        if r == "LOW":      return C_GREEN
        return C_GRAY

    def risk_bg(r):
        r = (r or "").upper()
        if r == "CRITICAL": return C_RED_BG
        if r == "HIGH":     return C_ORANGE_BG
        if r == "MEDIUM":   return C_YELLOW_BG
        if r == "LOW":      return C_GREEN_BG
        return C_LT_GRAY

    def risk_border(r):
        r = (r or "").upper()
        if r == "CRITICAL": return C_RED_BD
        if r == "HIGH":     return C_ORANGE_BD
        if r == "MEDIUM":   return C_ORANGE_BD
        if r == "LOW":      return C_GREEN_BD
        return C_BORDER

    pdf_path = f"/tmp/vulnforge_report_{target.replace('.', '_')}.pdf"

    PAGE_W, PAGE_H = A4
    MARGIN = 1.8*cm
    CONTENT_W = PAGE_W - 2*MARGIN

    S = getSampleStyleSheet()

    def sty(name, **kw):
        defaults = {'fontName': 'Helvetica'}
        defaults.update(kw)
        return ParagraphStyle(name, parent=S['Normal'], **defaults)

    # Style definitions
    s_title      = sty('title',    fontSize=22, fontName='Helvetica-Bold', textColor=colors.white,   leading=28)
    s_subtitle   = sty('sub',      fontSize=10, fontName='Helvetica',      textColor=colors.HexColor('#94A3B8'), leading=14)
    s_section    = sty('section',  fontSize=12, fontName='Helvetica-Bold', textColor=C_DARK,          leading=16, spaceBefore=6, spaceAfter=4)
    s_body       = sty('body',     fontSize=9.5,fontName='Helvetica',      textColor=C_MED_GRAY,      leading=15, spaceAfter=4)
    s_mono       = sty('mono',     fontSize=8.5,fontName='Courier',        textColor=C_MED_GRAY,      leading=13)
    s_label      = sty('label',    fontSize=8,  fontName='Helvetica-Bold', textColor=C_GRAY,          leading=11)
    s_wht_bold   = sty('whtbold',  fontSize=8.5,fontName='Helvetica-Bold', textColor=colors.white)
    s_wht        = sty('wht',      fontSize=8.5,fontName='Helvetica',      textColor=colors.white)
    s_small_gray = sty('smgray',   fontSize=8,  fontName='Helvetica',      textColor=C_GRAY,          leading=11)
    s_center     = sty('ctr',      fontSize=9,  fontName='Helvetica',      textColor=C_MED_GRAY,      alignment=TA_CENTER, leading=14)
    s_center_b   = sty('ctrb',     fontSize=9,  fontName='Helvetica-Bold', textColor=C_DARK,          alignment=TA_CENTER, leading=14)
    s_right      = sty('rgt',      fontSize=9,  fontName='Helvetica',      textColor=C_MED_GRAY,      alignment=TA_RIGHT)

    def brd(c=None):
        c = c or C_BORDER
        from reportlab.platypus import TableStyle
        b = {'style': 'LINEBELOW', 'color': c}
        return {'top': {'style':'LINEABOVE','size':0.5,'color':c}, 'bottom':{'style':'LINEBELOW','size':0.5,'color':c}, 'left':{'style':'LINEBEFORE','size':0.5,'color':c}, 'right':{'style':'LINEAFTER','size':0.5,'color':c}}

    def cell_pad(top=5, bot=5, left=8, right=8):
        return [('TOPPADDING',(0,0),(-1,-1),top),('BOTTOMPADDING',(0,0),(-1,-1),bot),('LEFTPADDING',(0,0),(-1,-1),left),('RIGHTPADDING',(0,0),(-1,-1),right)]

    # ── Header & Footer on every page ─────────────────────────────────────────
    GITHUB_URL   = "github.com/harman1418"
    LINKEDIN_URL = "linkedin.com/in/harmanjotcs"

    def draw_page_header_footer(canvas, doc):
        canvas.saveState()
        pw, ph = A4

        # ── Header bar ────────────────────────────────────────────────────────
        canvas.setFillColor(C_HEADER_BG)
        canvas.rect(0, ph - 1.1*cm, pw, 1.1*cm, fill=1, stroke=0)

        # Left: VulnForge logo text + scan info
        canvas.setFillColor(C_ACCENT)
        canvas.setFont("Helvetica-Bold", 10)
        canvas.drawString(MARGIN, ph - 0.72*cm, "VulnForge")

        canvas.setFillColor(colors.HexColor('#64748B'))
        canvas.setFont("Helvetica", 8)
        canvas.drawString(MARGIN + 65, ph - 0.72*cm, f"Penetration Test Report  |  {target}  |  {scan_label}")

        # Right: Page number
        canvas.setFillColor(colors.HexColor('#94A3B8'))
        canvas.setFont("Helvetica", 8)
        page_text = f"Page {doc.page}"
        canvas.drawRightString(pw - MARGIN, ph - 0.72*cm, page_text)

        # ── Footer bar ────────────────────────────────────────────────────────
        canvas.setFillColor(C_LT_GRAY)
        canvas.rect(0, 0, pw, 0.9*cm, fill=1, stroke=0)

        # Top line of footer
        canvas.setStrokeColor(C_BORDER)
        canvas.setLineWidth(0.5)
        canvas.line(0, 0.9*cm, pw, 0.9*cm)

        # Left: copyright
        canvas.setFillColor(C_GRAY)
        canvas.setFont("Helvetica", 7.5)
        canvas.drawString(MARGIN, 0.32*cm, f"Generated by VulnForge  |  {__import__('datetime').datetime.now().strftime('%Y-%m-%d %H:%M')} UTC  |  For authorized security testing only.")

        # Right: GitHub + LinkedIn
        canvas.setFillColor(C_ACCENT)
        canvas.setFont("Helvetica", 7.5)
        link_text = f"github.com/harman1418   linkedin.com/in/harmanjotcs"
        canvas.drawRightString(pw - MARGIN, 0.32*cm, link_text)

        canvas.restoreState()

    # ── Build document with custom template ───────────────────────────────────
    doc = BaseDocTemplate(
        pdf_path, pagesize=A4,
        rightMargin=MARGIN, leftMargin=MARGIN,
        topMargin=1.5*cm, bottomMargin=1.3*cm,
        title=f"VulnForge Penetration Test Report - {target}",
        author="VulnForge"
    )

    frame = Frame(MARGIN, 1.3*cm, CONTENT_W, PAGE_H - 2.6*cm, id='main')
    template = PageTemplate(id='main', frames=[frame], onPage=draw_page_header_footer)
    doc.addPageTemplates([template])

    story = []

    # ── COVER PAGE ────────────────────────────────────────────────────────────

    # Dark navy cover banner
    cover_top = Table([[
        Paragraph(f"<b>{target.upper()}</b>", sty('ct', fontSize=20, fontName='Helvetica-Bold', textColor=colors.white, leading=26)),
        Paragraph(f"<b>{risk}</b>", sty('cr', fontSize=16, fontName='Helvetica-Bold', textColor=risk_color(risk), alignment=TA_RIGHT, leading=22)),
    ],[
        Paragraph(f"Penetration Test Report  |  {scan_label}", s_subtitle),
        Paragraph(f"CVSS: {ai_analysis.get('security_score', 0)}/10.0", sty('cs', fontSize=13, fontName='Helvetica-Bold', textColor=risk_color(risk), alignment=TA_RIGHT)),
    ],[
        Paragraph(f"Scan Date: {__import__('datetime').datetime.now().strftime('%B %d, %Y')}", s_subtitle),
        Paragraph("", s_subtitle),
    ]], colWidths=[CONTENT_W*0.65, CONTENT_W*0.35])

    cover_top.setStyle(TableStyle([
        ('BACKGROUND', (0,0),(-1,-1), C_HEADER_BG),
        ('TOPPADDING', (0,0),(-1,-1), 14),
        ('BOTTOMPADDING', (0,0),(-1,-1), 14),
        ('LEFTPADDING', (0,0),(-1,-1), 16),
        ('RIGHTPADDING', (0,0),(-1,-1), 16),
        ('VALIGN', (0,0),(-1,-1), 'MIDDLE'),
        ('LINEBELOW', (0,1),(-1,1), 0.5, colors.HexColor('#334155')),
    ]))
    story.append(cover_top)
    story.append(Spacer(1, 0.5*cm))

    # Stats row
    ports      = scan_results.get("portscan",  {}).get("ports", [])
    subdomains = scan_results.get("subdomain", {}).get("subdomains", [])
    findings_c = len(ai_analysis.get("critical_findings", []))
    nuclei_c   = scan_results.get("nuclei",   {}).get("total", 0)

    def stat_cell(value, label, color=C_ACCENT):
        return Table([[
            Paragraph(str(value), sty('sv', fontSize=26, fontName='Helvetica-Bold', textColor=color, alignment=TA_CENTER, leading=30)),
        ],[
            Paragraph(label, sty('sl', fontSize=8, fontName='Helvetica', textColor=C_GRAY, alignment=TA_CENTER)),
        ]], colWidths=[CONTENT_W/4 - 4])

    stats_row = Table([[
        stat_cell(len(ports), "Open Ports", C_BLUE),
        stat_cell(len(subdomains), "Subdomains", C_ACCENT),
        stat_cell(findings_c, "AI Findings", risk_color(risk)),
        stat_cell(nuclei_c, "CVEs Found", C_RED),
    ]], colWidths=[CONTENT_W/4]*4)
    stats_row.setStyle(TableStyle([
        ('BACKGROUND', (0,0),(-1,-1), C_LT_GRAY),
        ('BOX', (0,0),(-1,-1), 0.5, C_BORDER),
        ('LINEAFTER', (0,0),(2,0), 0.5, C_BORDER),
        ('TOPPADDING', (0,0),(-1,-1), 10),
        ('BOTTOMPADDING', (0,0),(-1,-1), 10),
        ('ALIGN', (0,0),(-1,-1), 'CENTER'),
    ]))
    story.append(stats_row)
    story.append(Spacer(1, 0.6*cm))

    # ── SECTION HELPER ────────────────────────────────────────────────────────

    def section_header(number, title, color=C_ACCENT):
        tbl = Table([[
            Paragraph(f"<b>{number}</b>", sty('sn', fontSize=10, fontName='Helvetica-Bold', textColor=colors.white, alignment=TA_CENTER)),
            Paragraph(f"<b>{title}</b>", sty('st', fontSize=11, fontName='Helvetica-Bold', textColor=C_DARK)),
        ]], colWidths=[0.7*cm, CONTENT_W - 0.7*cm])
        tbl.setStyle(TableStyle([
            ('BACKGROUND', (0,0),(0,0), color),
            ('BACKGROUND', (1,0),(1,0), C_LT_GRAY),
            ('TOPPADDING', (0,0),(-1,-1), 7),
            ('BOTTOMPADDING', (0,0),(-1,-1), 7),
            ('LEFTPADDING', (0,0),(0,0), 0),
            ('LEFTPADDING', (1,0),(1,0), 10),
            ('RIGHTPADDING', (0,0),(-1,-1), 8),
            ('BOX', (0,0),(-1,-1), 0.5, C_BORDER),
            ('ALIGN', (0,0),(0,0), 'CENTER'),
            ('VALIGN', (0,0),(-1,-1), 'MIDDLE'),
        ]))
        return tbl

    def badge(text, color, bg):
        t = Table([[Paragraph(f"<b>{text}</b>", sty('b', fontSize=8, fontName='Helvetica-Bold', textColor=color, alignment=TA_CENTER))]])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0,0),(-1,-1), bg),
            ('TOPPADDING', (0,0),(-1,-1), 3),
            ('BOTTOMPADDING', (0,0),(-1,-1), 3),
            ('LEFTPADDING', (0,0),(-1,-1), 8),
            ('RIGHTPADDING', (0,0),(-1,-1), 8),
            ('BOX', (0,0),(-1,-1), 0.5, color),
            ('ROUNDEDCORNERS', [3]),
        ]))
        return t

    # ── 01 EXECUTIVE SUMMARY ──────────────────────────────────────────────────
    story.append(section_header("01", "EXECUTIVE SUMMARY"))
    story.append(Spacer(1, 0.3*cm))
    story.append(Paragraph(ai_analysis.get("executive_summary", "No summary available."), s_body))
    story.append(Spacer(1, 0.4*cm))

    # Risk overview table
    os_info = scan_results.get("portscan", {}).get("os", "")
    risk_rows = [
        [Paragraph("Overall Risk", s_label), Paragraph(f"<b>{risk}</b>", sty('rr', fontSize=13, fontName='Helvetica-Bold', textColor=risk_color(risk)))],
        [Paragraph("CVSS Score", s_label), Paragraph(f"<b>{ai_analysis.get('security_score', 0)} / 10.0</b>", sty('sr', fontSize=13, fontName='Helvetica-Bold', textColor=C_DARK))],
        [Paragraph("Scan Type", s_label), Paragraph(f"<b>{scan_label}</b>", sty('str', fontSize=11, fontName='Helvetica-Bold', textColor=C_BLUE))],
        [Paragraph("Scan Date", s_label), Paragraph(__import__('datetime').datetime.now().strftime('%Y-%m-%d %H:%M UTC'), s_body)],
    ]
    if os_info:
        risk_rows.append([Paragraph("Detected OS", s_label), Paragraph(os_info, s_body)])

    risk_tbl = Table(risk_rows, colWidths=[3.5*cm, CONTENT_W - 3.5*cm])
    risk_tbl.setStyle(TableStyle([
        ('BACKGROUND', (0,0),(0,-1), C_LT_GRAY),
        ('TOPPADDING', (0,0),(-1,-1), 6),
        ('BOTTOMPADDING', (0,0),(-1,-1), 6),
        ('LEFTPADDING', (0,0),(-1,-1), 10),
        ('RIGHTPADDING', (0,0),(-1,-1), 10),
        ('VALIGN', (0,0),(-1,-1), 'MIDDLE'),
        ('ROWBACKGROUNDS', (1,0),(1,-1), [colors.white, C_LT_GRAY]),
        ('BOX', (0,0),(-1,-1), 0.5, C_BORDER),
        ('INNERGRID', (0,0),(-1,-1), 0.3, C_BORDER),
    ]))
    story.append(risk_tbl)
    story.append(Spacer(1, 0.6*cm))

    # ── 02 CRITICAL FINDINGS ──────────────────────────────────────────────────
    crit = ai_analysis.get("critical_findings", [])
    if crit:
        story.append(section_header("02", f"CRITICAL FINDINGS  ({len(crit)} identified)", C_RED))
        story.append(Spacer(1, 0.3*cm))

        for i, finding in enumerate(crit, 1):
            sev = (finding.get("severity") or "MEDIUM").upper()
            fc  = risk_color(sev)
            fbg = risk_bg(sev)
            fbd = risk_border(sev)

            # Finding header
            find_hdr = Table([[
                Paragraph(f"<b>{i:02d}.  {finding.get('title','')}</b>",
                    sty('fh', fontSize=10, fontName='Helvetica-Bold', textColor=C_DARK)),
                Paragraph(f"<b>{sev}</b>",
                    sty('fs', fontSize=8, fontName='Helvetica-Bold', textColor=fc, alignment=TA_RIGHT)),
            ]], colWidths=[CONTENT_W - 2.5*cm, 2.5*cm])
            find_hdr.setStyle(TableStyle([
                ('BACKGROUND', (0,0),(-1,-1), fbg),
                ('TOPPADDING', (0,0),(-1,-1), 8),
                ('BOTTOMPADDING', (0,0),(-1,-1), 8),
                ('LEFTPADDING', (0,0),(-1,-1), 10),
                ('RIGHTPADDING', (0,0),(-1,-1), 10),
                ('VALIGN', (0,0),(-1,-1), 'MIDDLE'),
                ('LINEBELOW', (0,0),(-1,-1), 1.5, fc),
                ('LINEBEFORE', (0,0),(0,-1), 3, fc),
            ]))
            story.append(find_hdr)

            # Finding body
            body_rows = [[
                Paragraph("Description", s_label),
                Paragraph(finding.get("description",""), s_body)
            ]]
            if finding.get("evidence"):
                body_rows.append([
                    Paragraph("Evidence", s_label),
                    Paragraph(str(finding.get("evidence",""))[:300], s_mono)
                ])

            find_body = Table(body_rows, colWidths=[2.5*cm, CONTENT_W - 2.5*cm])
            find_body.setStyle(TableStyle([
                ('BACKGROUND', (0,0),(0,-1), C_LT_GRAY),
                ('BACKGROUND', (1,0),(1,-1), colors.white),
                ('TOPPADDING', (0,0),(-1,-1), 6),
                ('BOTTOMPADDING', (0,0),(-1,-1), 6),
                ('LEFTPADDING', (0,0),(-1,-1), 10),
                ('RIGHTPADDING', (0,0),(-1,-1), 10),
                ('VALIGN', (0,0),(-1,-1), 'TOP'),
                ('BOX', (0,0),(-1,-1), 0.5, C_BORDER),
                ('INNERGRID', (0,0),(-1,-1), 0.3, C_BORDER),
                ('LINEBEFORE', (0,0),(0,-1), 3, fc),
            ]))
            story.append(find_body)
            story.append(Spacer(1, 0.25*cm))

        story.append(Spacer(1, 0.4*cm))

    # ── 03 PORT SCAN ──────────────────────────────────────────────────────────
    if ports:
        story.append(section_header("03", f"OPEN PORTS & SERVICES  ({len(ports)} found)", C_BLUE))
        story.append(Spacer(1, 0.3*cm))

        port_rows = [[
            Paragraph("PORT", s_wht_bold),
            Paragraph("PROTO", s_wht_bold),
            Paragraph("SERVICE", s_wht_bold),
            Paragraph("VERSION / BANNER", s_wht_bold),
        ]]
        for p in ports:
            ver = (p.get("version","") or p.get("extrainfo",""))[:55]
            port_rows.append([
                Paragraph(f"<b>{p.get('port','')}</b>", sty('pt', fontSize=9, fontName='Helvetica-Bold', textColor=C_BLUE)),
                Paragraph(str(p.get("protocol","")), s_body),
                Paragraph(str(p.get("service","")), s_body),
                Paragraph(str(ver), s_mono),
            ])

        pt = Table(port_rows, colWidths=[1.6*cm, 2*cm, 3.5*cm, CONTENT_W - 7.1*cm])
        pt.setStyle(TableStyle([
            ('BACKGROUND', (0,0),(-1,0), C_HEADER_BG),
            ('ROWBACKGROUNDS', (0,1),(-1,-1), [colors.white, C_LT_GRAY]),
            ('TOPPADDING', (0,0),(-1,-1), 6),
            ('BOTTOMPADDING', (0,0),(-1,-1), 6),
            ('LEFTPADDING', (0,0),(-1,-1), 8),
            ('RIGHTPADDING', (0,0),(-1,-1), 8),
            ('VALIGN', (0,0),(-1,-1), 'MIDDLE'),
            ('BOX', (0,0),(-1,-1), 0.5, C_BORDER),
            ('INNERGRID', (0,0),(-1,-1), 0.3, C_BORDER),
        ]))
        story.append(pt)
        story.append(Spacer(1, 0.6*cm))

    # ── 04 SUBDOMAINS ─────────────────────────────────────────────────────────
    if subdomains:
        story.append(section_header("04", f"SUBDOMAINS DISCOVERED  ({len(subdomains)} found)", C_BLUE))
        story.append(Spacer(1, 0.3*cm))

        display = subdomains[:60]
        rows = []
        for i in range(0, len(display), 3):
            row = []
            for j in range(3):
                val = display[i+j] if i+j < len(display) else ""
                row.append(Paragraph(val, s_mono))
            rows.append(row)

        st = Table(rows, colWidths=[CONTENT_W/3]*3)
        st.setStyle(TableStyle([
            ('ROWBACKGROUNDS', (0,0),(-1,-1), [colors.white, C_LT_GRAY]),
            ('TOPPADDING', (0,0),(-1,-1), 5),
            ('BOTTOMPADDING', (0,0),(-1,-1), 5),
            ('LEFTPADDING', (0,0),(-1,-1), 8),
            ('RIGHTPADDING', (0,0),(-1,-1), 8),
            ('BOX', (0,0),(-1,-1), 0.5, C_BORDER),
            ('INNERGRID', (0,0),(-1,-1), 0.3, C_BORDER),
        ]))
        story.append(st)
        if len(subdomains) > 60:
            story.append(Spacer(1, 0.15*cm))
            story.append(Paragraph(f"... and {len(subdomains)-60} more subdomains discovered.", s_small_gray))
        story.append(Spacer(1, 0.6*cm))

    # ── 05 TECHNOLOGY & SECURITY HEADERS ─────────────────────────────────────
    techs    = scan_results.get("headers",{}).get("technologies",{})
    sec_hdrs = scan_results.get("headers",{}).get("security_headers",{})
    dns_info = scan_results.get("dns",{}).get("records",{})

    if techs or sec_hdrs or dns_info:
        story.append(section_header("05", "TECHNOLOGY & HEADER ANALYSIS", C_BLUE))
        story.append(Spacer(1, 0.3*cm))

        if techs:
            story.append(Paragraph("<b>Technologies Detected</b>", sty('th', fontSize=10, fontName='Helvetica-Bold', textColor=C_DARK, spaceAfter=5)))
            items = [item for vals in techs.values() for item in vals]
            if items:
                rows = []
                for i in range(0, len(items), 4):
                    rows.append([Paragraph(items[j] if j < len(items) else "", s_mono) for j in range(i, i+4)])
                tt = Table(rows, colWidths=[CONTENT_W/4]*4)
                tt.setStyle(TableStyle([
                    ('ROWBACKGROUNDS', (0,0),(-1,-1), [colors.white, C_LT_GRAY]),
                    ('TOPPADDING', (0,0),(-1,-1), 5),
                    ('BOTTOMPADDING', (0,0),(-1,-1), 5),
                    ('LEFTPADDING', (0,0),(-1,-1), 8),
                    ('RIGHTPADDING', (0,0),(-1,-1), 8),
                    ('BOX', (0,0),(-1,-1), 0.5, C_BORDER),
                    ('INNERGRID', (0,0),(-1,-1), 0.3, C_BORDER),
                ]))
                story.append(tt)
                story.append(Spacer(1, 0.4*cm))

        if sec_hdrs:
            story.append(Paragraph("<b>Security Headers</b>", sty('sh', fontSize=10, fontName='Helvetica-Bold', textColor=C_DARK, spaceAfter=5)))
            hrows = [[Paragraph("HEADER", s_wht_bold), Paragraph("STATUS", s_wht_bold), Paragraph("VALUE", s_wht_bold)]]
            for h, v in sec_hdrs.items():
                not_set = "NOT SET" in str(v) or "Missing" in str(v)
                status_color = C_RED if not_set else C_GREEN
                status_bg    = C_RED_BG if not_set else C_GREEN_BG
                status_text  = "MISSING" if not_set else "SET"
                hrows.append([
                    Paragraph(h, s_body),
                    Table([[Paragraph(f"<b>{status_text}</b>", sty('st', fontSize=8, fontName='Helvetica-Bold', textColor=status_color, alignment=TA_CENTER))]],
                        colWidths=[1.8*cm],
                        style=TableStyle([('BACKGROUND',(0,0),(-1,-1),status_bg),('TOPPADDING',(0,0),(-1,-1),3),('BOTTOMPADDING',(0,0),(-1,-1),3),('BOX',(0,0),(-1,-1),0.5,status_color)])
                    ),
                    Paragraph("Not configured" if not_set else str(v)[:70], s_mono),
                ])

            ht = Table(hrows, colWidths=[5*cm, 2.2*cm, CONTENT_W - 7.2*cm])
            ht.setStyle(TableStyle([
                ('BACKGROUND', (0,0),(-1,0), C_HEADER_BG),
                ('ROWBACKGROUNDS', (0,1),(-1,-1), [colors.white, C_LT_GRAY]),
                ('TOPPADDING', (0,0),(-1,-1), 6),
                ('BOTTOMPADDING', (0,0),(-1,-1), 6),
                ('LEFTPADDING', (0,0),(-1,-1), 8),
                ('RIGHTPADDING', (0,0),(-1,-1), 8),
                ('VALIGN', (0,0),(-1,-1), 'MIDDLE'),
                ('BOX', (0,0),(-1,-1), 0.5, C_BORDER),
                ('INNERGRID', (0,0),(-1,-1), 0.3, C_BORDER),
            ]))
            story.append(ht)
            story.append(Spacer(1, 0.4*cm))

        if dns_info:
            story.append(Paragraph("<b>DNS Records</b>", sty('dr', fontSize=10, fontName='Helvetica-Bold', textColor=C_DARK, spaceAfter=5)))
            drows = [[Paragraph("TYPE", s_wht_bold), Paragraph("RECORDS", s_wht_bold)]]
            for rtype, vals in dns_info.items():
                drows.append([
                    Paragraph(f"<b>{rtype}</b>", sty('dt', fontSize=9, fontName='Helvetica-Bold', textColor=C_BLUE)),
                    Paragraph(", ".join(str(v) for v in vals[:5]), s_mono)
                ])
            dt = Table(drows, colWidths=[2*cm, CONTENT_W - 2*cm])
            dt.setStyle(TableStyle([
                ('BACKGROUND', (0,0),(-1,0), C_HEADER_BG),
                ('ROWBACKGROUNDS', (0,1),(-1,-1), [colors.white, C_LT_GRAY]),
                ('TOPPADDING', (0,0),(-1,-1), 6),
                ('BOTTOMPADDING', (0,0),(-1,-1), 6),
                ('LEFTPADDING', (0,0),(-1,-1), 8),
                ('RIGHTPADDING', (0,0),(-1,-1), 8),
                ('BOX', (0,0),(-1,-1), 0.5, C_BORDER),
                ('INNERGRID', (0,0),(-1,-1), 0.3, C_BORDER),
            ]))
            story.append(dt)
            story.append(Spacer(1, 0.6*cm))

    # ── 06 SSL/TLS & WAF SECURITY ────────────────────────────────────────────
    waf_info = scan_results.get("waf", {})
    ssl_info = scan_results.get("ssl", {})

    if waf_info or ssl_info:
        story.append(section_header("06", "SSL/TLS & WAF SECURITY ANALYSIS", C_BLUE))
        story.append(Spacer(1, 0.3*cm))

        sec_rows = []
        if waf_info:
            detected = waf_info.get("detected", False)
            waf_status = "ACTIVE" if detected else "NOT DETECTED"
            waf_color = C_GREEN if detected else C_ORANGE
            waf_bg = C_GREEN_BG if detected else C_ORANGE_BG
            waf_detail = waf_info.get("waf", "No Web Application Firewall was identified.")
            
            sec_rows.append([
                Paragraph("<b>WAF Protection</b>", s_body),
                Table([[Paragraph(f"<b>{waf_status}</b>", sty('ws', fontSize=8, fontName='Helvetica-Bold', textColor=waf_color, alignment=TA_CENTER))]],
                    colWidths=[2.8*cm],
                    style=TableStyle([('BACKGROUND',(0,0),(-1,-1),waf_bg),('TOPPADDING',(0,0),(-1,-1),3),('BOTTOMPADDING',(0,0),(-1,-1),3),('BOX',(0,0),(-1,-1),0.5,waf_color)])
                ),
                Paragraph(waf_detail, s_body)
            ])

        if ssl_info:
            # Handle SSL details beautifully
            tls_1_0 = ssl_info.get("tls_1_0", "Unknown")
            tls_1_1 = ssl_info.get("tls_1_1", "Unknown")
            tls_1_2 = ssl_info.get("tls_1_2", "Unknown")
            tls_1_3 = ssl_info.get("tls_1_3", "Unknown")
            
            is_vuln_ssl = "enabled" in str(tls_1_0).lower() or "enabled" in str(tls_1_1).lower()
            ssl_status = "VULNERABLE (TLS 1.0/1.1)" if is_vuln_ssl else "SECURE (Modern TLS)"
            ssl_color = C_RED if is_vuln_ssl else C_GREEN
            ssl_bg = C_RED_BG if is_vuln_ssl else C_GREEN_BG
            
            ssl_desc = f"TLS 1.2: {tls_1_2} | TLS 1.3: {tls_1_3}"
            if is_vuln_ssl:
                ssl_desc += " — Warning: Legacy TLS 1.0/1.1 protocols are enabled. Risk of interception/POODLE attacks."
            else:
                ssl_desc += " — Legacies (TLS 1.0/1.1) are disabled. Modern cipher suites enforced."

            sec_rows.append([
                Paragraph("<b>SSL/TLS Ciphers</b>", s_body),
                Table([[Paragraph(f"<b>{ssl_status}</b>", sty('ss', fontSize=8, fontName='Helvetica-Bold', textColor=ssl_color, alignment=TA_CENTER))]],
                    colWidths=[2.8*cm],
                    style=TableStyle([('BACKGROUND',(0,0),(-1,-1),ssl_bg),('TOPPADDING',(0,0),(-1,-1),3),('BOTTOMPADDING',(0,0),(-1,-1),3),('BOX',(0,0),(-1,-1),0.5,ssl_color)])
                ),
                Paragraph(ssl_desc, s_body)
            ])

        if sec_rows:
            sect = Table(sec_rows, colWidths=[3.5*cm, 3.2*cm, CONTENT_W - 6.7*cm])
            sect.setStyle(TableStyle([
                ('ROWBACKGROUNDS', (0,0),(-1,-1), [colors.white, C_LT_GRAY]),
                ('TOPPADDING', (0,0),(-1,-1), 8),
                ('BOTTOMPADDING', (0,0),(-1,-1), 8),
                ('LEFTPADDING', (0,0),(-1,-1), 8),
                ('RIGHTPADDING', (0,0),(-1,-1), 8),
                ('VALIGN', (0,0),(-1,-1), 'MIDDLE'),
                ('BOX', (0,0),(-1,-1), 0.5, C_BORDER),
                ('INNERGRID', (0,0),(-1,-1), 0.3, C_BORDER),
            ]))
            story.append(sect)
            story.append(Spacer(1, 0.6*cm))

    # ── 07 CORE SURFACE WEAKNESSES ───────────────────────────────────────────
    cookie_info = scan_results.get("cookie", {})
    click_info = scan_results.get("clickjacking", {})
    robots_info = scan_results.get("robots", {})
    takeover_info = scan_results.get("subdomain_takeover", {})

    has_surface = cookie_info or click_info or robots_info or takeover_info
    if has_surface:
        story.append(section_header("07", "CORE SURFACE WEAKNESSES & RISKS", C_BLUE))
        story.append(Spacer(1, 0.3*cm))

        weakness_rows = []

        # 1. Cookie Security Check
        if cookie_info and cookie_info.get("status") == "success":
            vuln_cookies = cookie_info.get("vulnerable_cookies", 0)
            total_cookies = cookie_info.get("total_cookies", 0)
            status_text = f"{vuln_cookies}/{total_cookies} WEAK" if vuln_cookies > 0 else "SECURE"
            status_color = C_RED if vuln_cookies > 0 else C_GREEN
            status_bg = C_RED_BG if vuln_cookies > 0 else C_GREEN_BG
            
            issues = ", ".join(cookie_info.get("issues_summary", []))
            desc = f"Analyzed {total_cookies} cookies. " + (f"Vulnerabilities found: {issues}" if vuln_cookies > 0 else "All cookies have Secure & HttpOnly flags set.")
            weakness_rows.append([
                Paragraph("<b>Session Cookies</b>", s_body),
                Table([[Paragraph(f"<b>{status_text}</b>", sty('cs', fontSize=8, fontName='Helvetica-Bold', textColor=status_color, alignment=TA_CENTER))]],
                    colWidths=[2.8*cm],
                    style=TableStyle([('BACKGROUND',(0,0),(-1,-1),status_bg),('TOPPADDING',(0,0),(-1,-1),3),('BOTTOMPADDING',(0,0),(-1,-1),3),('BOX',(0,0),(-1,-1),0.5,status_color)])
                ),
                Paragraph(desc, s_body)
            ])

        # 2. Clickjacking Protection Check
        if click_info and click_info.get("status") == "success":
            vulnerable = click_info.get("is_vulnerable", True)
            status_text = "VULNERABLE" if vulnerable else "SECURE"
            status_color = C_RED if vulnerable else C_GREEN
            status_bg = C_RED_BG if vulnerable else C_GREEN_BG
            
            protections = ", ".join(click_info.get("protections", []))
            desc = "Target is vulnerable to Clickjacking (missing X-Frame-Options & CSP frame-ancestors)." if vulnerable else f"Protected via {protections} headers."
            weakness_rows.append([
                Paragraph("<b>Clickjacking</b>", s_body),
                Table([[Paragraph(f"<b>{status_text}</b>", sty('cl', fontSize=8, fontName='Helvetica-Bold', textColor=status_color, alignment=TA_CENTER))]],
                    colWidths=[2.8*cm],
                    style=TableStyle([('BACKGROUND',(0,0),(-1,-1),status_bg),('TOPPADDING',(0,0),(-1,-1),3),('BOTTOMPADDING',(0,0),(-1,-1),3),('BOX',(0,0),(-1,-1),0.5,status_color)])
                ),
                Paragraph(desc, s_body)
            ])

        # 3. Robots.txt Analysis
        if robots_info and robots_info.get("status") == "success":
            found = robots_info.get("found", False)
            status_text = f"FOUND ({robots_info.get('disallowed_count', 0)})" if found else "NOT FOUND"
            status_color = C_ORANGE if found else C_GREEN
            status_bg = C_ORANGE_BG if found else C_GREEN_BG
            
            paths = robots_info.get("sensitive_paths_found", [])
            desc = "Robots.txt is missing on target."
            if found:
                desc = f"Exposes {robots_info.get('disallowed_count', 0)} disallowed paths."
                if paths:
                    desc += f" Exposed sensitive directories: {', '.join(paths[:4])}"
            weakness_rows.append([
                Paragraph("<b>Robots.txt Intel</b>", s_body),
                Table([[Paragraph(f"<b>{status_text}</b>", sty('rb', fontSize=8, fontName='Helvetica-Bold', textColor=status_color, alignment=TA_CENTER))]],
                    colWidths=[2.8*cm],
                    style=TableStyle([('BACKGROUND',(0,0),(-1,-1),status_bg),('TOPPADDING',(0,0),(-1,-1),3),('BOTTOMPADDING',(0,0),(-1,-1),3),('BOX',(0,0),(-1,-1),0.5,status_color)])
                ),
                Paragraph(desc, s_body)
            ])

        # 4. Subdomain Takeover Check
        if takeover_info and takeover_info.get("status") == "success":
            vuln_count = takeover_info.get("vulnerable_count", 0)
            status_text = "VULNERABLE" if vuln_count > 0 else "SECURE"
            status_color = C_RED if vuln_count > 0 else C_GREEN
            status_bg = C_RED_BG if vuln_count > 0 else C_GREEN_BG
            
            checked = takeover_info.get("subdomains_checked", 0)
            desc = f"Checked {checked} subdomains for dangling DNS records."
            if vuln_count > 0:
                vuln_domains = [v.get("subdomain") for v in takeover_info.get("vulnerable", [])]
                desc += f" WARNING: Identified {vuln_count} vulnerable dangling domains: {', '.join(vuln_domains)}"
            else:
                desc += " No dangling CNAME/DNS configuration issues found."
                
            weakness_rows.append([
                Paragraph("<b>Subdomain Takeover</b>", s_body),
                Table([[Paragraph(f"<b>{status_text}</b>", sty('tk', fontSize=8, fontName='Helvetica-Bold', textColor=status_color, alignment=TA_CENTER))]],
                    colWidths=[2.8*cm],
                    style=TableStyle([('BACKGROUND',(0,0),(-1,-1),status_bg),('TOPPADDING',(0,0),(-1,-1),3),('BOTTOMPADDING',(0,0),(-1,-1),3),('BOX',(0,0),(-1,-1),0.5,status_color)])
                ),
                Paragraph(desc, s_body)
            ])

        if weakness_rows:
            wt = Table(weakness_rows, colWidths=[3.5*cm, 3.2*cm, CONTENT_W - 6.7*cm])
            wt.setStyle(TableStyle([
                ('ROWBACKGROUNDS', (0,0),(-1,-1), [colors.white, C_LT_GRAY]),
                ('TOPPADDING', (0,0),(-1,-1), 8),
                ('BOTTOMPADDING', (0,0),(-1,-1), 8),
                ('LEFTPADDING', (0,0),(-1,-1), 8),
                ('RIGHTPADDING', (0,0),(-1,-1), 8),
                ('VALIGN', (0,0),(-1,-1), 'MIDDLE'),
                ('BOX', (0,0),(-1,-1), 0.5, C_BORDER),
                ('INNERGRID', (0,0),(-1,-1), 0.3, C_BORDER),
            ]))
            story.append(wt)
            story.append(Spacer(1, 0.6*cm))

    # ── 08 CVE / NUCLEI ───────────────────────────────────────────────────────
    nuclei_findings = scan_results.get("nuclei", {}).get("findings", [])
    if nuclei_findings:
        story.append(section_header("08", f"CVE / VULNERABILITY FINDINGS  ({len(nuclei_findings)} found)", C_RED))
        story.append(Spacer(1, 0.3*cm))
        nrows = [[Paragraph(h, s_wht_bold) for h in ["SEVERITY","TEMPLATE ID","VULNERABILITY NAME","MATCHED AT"]]]
        for nf in nuclei_findings[:30]:
            sev = (nf.get("severity","") or "").upper()
            nrows.append([
                Paragraph(f"<b>{sev}</b>", sty('ns', fontSize=8, fontName='Helvetica-Bold', textColor=risk_color(sev))),
                Paragraph(str(nf.get("template",""))[:28], s_mono),
                Paragraph(str(nf.get("name",""))[:45], s_body),
                Paragraph(str(nf.get("matched_at",""))[:40], s_mono),
            ])
        nt = Table(nrows, colWidths=[2*cm, 3.5*cm, 6*cm, CONTENT_W - 11.5*cm])
        nt.setStyle(TableStyle([
            ('BACKGROUND', (0,0),(-1,0), C_HEADER_BG),
            ('ROWBACKGROUNDS', (0,1),(-1,-1), [colors.white, C_LT_GRAY]),
            ('TOPPADDING', (0,0),(-1,-1), 6),
            ('BOTTOMPADDING', (0,0),(-1,-1), 6),
            ('LEFTPADDING', (0,0),(-1,-1), 7),
            ('RIGHTPADDING', (0,0),(-1,-1), 7),
            ('BOX', (0,0),(-1,-1), 0.5, C_BORDER),
            ('INNERGRID', (0,0),(-1,-1), 0.3, C_BORDER),
        ]))
        story.append(nt)
        story.append(Spacer(1, 0.6*cm))

    # ── 09 AI ATTACK RESULTS ──────────────────────────────────────────────────
    if attack_results:
        story.append(section_header("09", f"AI-DIRECTED ATTACK RESULTS  ({len(attack_results)} executed)", C_ORANGE))
        story.append(Spacer(1, 0.3*cm))

        for a in attack_results:
            vuln = a.get("result",{}).get("vulnerable")
            vc   = C_RED if vuln else C_GREEN
            vbg  = C_RED_BG if vuln else C_GREEN_BG
            vtxt = "VULNERABLE" if vuln else "Not Vulnerable"

            at = Table([[
                Paragraph(f"<b>{a.get('tool','').upper()}</b>",
                    sty('atl', fontSize=10, fontName='Helvetica-Bold', textColor=C_ORANGE)),
                Paragraph(f"<b>{vtxt}</b>",
                    sty('av', fontSize=9, fontName='Helvetica-Bold', textColor=vc, alignment=TA_RIGHT)),
            ],[
                Paragraph(f"Target: {a.get('target','')}", s_small_gray),
                Paragraph(f"Priority: {a.get('priority','')}", sty('ap', fontSize=8, fontName='Helvetica', textColor=C_GRAY, alignment=TA_RIGHT)),
            ],[
                Paragraph(f"Reason: {a.get('reason','')}", s_body),
                "",
            ]], colWidths=[CONTENT_W*0.6, CONTENT_W*0.4])
            at.setStyle(TableStyle([
                ('BACKGROUND', (0,0),(-1,0), C_ORANGE_BG),
                ('BACKGROUND', (0,1),(-1,1), C_LT_GRAY),
                ('BACKGROUND', (0,2),(-1,2), colors.white),
                ('TOPPADDING', (0,0),(-1,-1), 7),
                ('BOTTOMPADDING', (0,0),(-1,-1), 7),
                ('LEFTPADDING', (0,0),(-1,-1), 10),
                ('RIGHTPADDING', (0,0),(-1,-1), 10),
                ('VALIGN', (0,0),(-1,-1), 'TOP'),
                ('BOX', (0,0),(-1,-1), 0.5, C_BORDER),
                ('INNERGRID', (0,0),(-1,-1), 0.3, C_BORDER),
                ('LINEBEFORE', (0,0),(0,-1), 3, C_ORANGE),
                ('SPAN', (0,2),(1,2)),
            ]))
            story.append(at)
            story.append(Spacer(1, 0.3*cm))
        story.append(Spacer(1, 0.4*cm))

    # ── 10 DOMAIN & WHOIS INTEL ──────────────────────────────────────────────
    whois_info = scan_results.get("whois", {}).get("data", {})
    if whois_info:
        story.append(section_header("10", "DOMAIN WHOIS INTEL", C_BLUE))
        story.append(Spacer(1, 0.3*cm))

        w_rows = [
            [Paragraph("Registrar", s_label), Paragraph(whois_info.get("registrar", "Not Available"), s_body)],
            [Paragraph("Registered Date", s_label), Paragraph(whois_info.get("creation_date", "Not Available"), s_body)],
            [Paragraph("Expiration Date", s_label), Paragraph(whois_info.get("expiration_date", "Not Available"), s_body)],
            [Paragraph("Name Servers", s_label), Paragraph(whois_info.get("name_servers", "Not Available"), s_body)],
            [Paragraph("Organization", s_label), Paragraph(whois_info.get("org", "Not Available"), s_body)],
            [Paragraph("Country", s_label), Paragraph(whois_info.get("country", "Not Available"), s_body)],
        ]
        
        wtbl = Table(w_rows, colWidths=[3.5*cm, CONTENT_W - 3.5*cm])
        wtbl.setStyle(TableStyle([
            ('BACKGROUND', (0,0),(0,-1), C_LT_GRAY),
            ('TOPPADDING', (0,0),(-1,-1), 6),
            ('BOTTOMPADDING', (0,0),(-1,-1), 6),
            ('LEFTPADDING', (0,0),(-1,-1), 10),
            ('RIGHTPADDING', (0,0),(-1,-1), 10),
            ('VALIGN', (0,0),(-1,-1), 'MIDDLE'),
            ('ROWBACKGROUNDS', (1,0),(1,-1), [colors.white, C_LT_GRAY]),
            ('BOX', (0,0),(-1,-1), 0.5, C_BORDER),
            ('INNERGRID', (0,0),(-1,-1), 0.3, C_BORDER),
        ]))
        story.append(wtbl)
        story.append(Spacer(1, 0.6*cm))

    # ── 11 REMEDIATION ────────────────────────────────────────────────────────
    rems = ai_analysis.get("remediation_steps", [])
    if rems:
        story.append(section_header("11", f"REMEDIATION RECOMMENDATIONS  ({len(rems)} steps)", C_GREEN))
        story.append(Spacer(1, 0.3*cm))

        for i, s in enumerate(rems, 1):
            pri = (s.get("priority","MEDIUM") or "MEDIUM").upper()
            pc  = risk_color(pri)
            pbg = risk_bg(pri)

            rem = Table([[
                Paragraph(f"<b>{i:02d}.  {s.get('issue','')}</b>",
                    sty('ri', fontSize=10, fontName='Helvetica-Bold', textColor=C_DARK)),
                Paragraph(f"<b>{pri}</b>",
                    sty('rp', fontSize=8, fontName='Helvetica-Bold', textColor=pc, alignment=TA_RIGHT)),
            ],[
                Paragraph(s.get("fix",""), s_body),
                "",
            ]], colWidths=[CONTENT_W - 2.5*cm, 2.5*cm])
            rem.setStyle(TableStyle([
                ('BACKGROUND', (0,0),(-1,0), pbg),
                ('BACKGROUND', (0,1),(-1,1), colors.white),
                ('TOPPADDING', (0,0),(-1,-1), 8),
                ('BOTTOMPADDING', (0,0),(-1,-1), 8),
                ('LEFTPADDING', (0,0),(-1,-1), 10),
                ('RIGHTPADDING', (0,0),(-1,-1), 10),
                ('VALIGN', (0,0),(-1,-1), 'TOP'),
                ('BOX', (0,0),(-1,-1), 0.5, C_BORDER),
                ('LINEBELOW', (0,0),(-1,0), 0.5, C_BORDER),
                ('LINEBEFORE', (0,0),(0,-1), 3, pc),
                ('SPAN', (0,1),(1,1)),
            ]))
            story.append(rem)
            story.append(Spacer(1, 0.25*cm))

    # ── DISCLAIMER ────────────────────────────────────────────────────────────
    story.append(Spacer(1, 0.8*cm))
    disclaimer = Table([[
        Paragraph(
            "<b>DISCLAIMER:</b> This report was generated by VulnForge for authorized security testing purposes only. "
            "All findings should be verified by a qualified security professional before remediation. "
            "Unauthorized use of this report or its contents is strictly prohibited.",
            sty('disc', fontSize=8, fontName='Helvetica', textColor=C_GRAY, leading=12))
    ]], colWidths=[CONTENT_W])
    disclaimer.setStyle(TableStyle([
        ('BACKGROUND', (0,0),(-1,-1), C_LT_GRAY),
        ('BOX', (0,0),(-1,-1), 0.5, C_BORDER),
        ('TOPPADDING', (0,0),(-1,-1), 8),
        ('BOTTOMPADDING', (0,0),(-1,-1), 8),
        ('LEFTPADDING', (0,0),(-1,-1), 10),
        ('RIGHTPADDING', (0,0),(-1,-1), 10),
    ]))
    story.append(disclaimer)

    doc.build(story)
    return pdf_path
