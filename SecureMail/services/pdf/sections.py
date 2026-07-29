from reportlab.platypus import Paragraph, Spacer, KeepTogether, Table, TableStyle, CondPageBreak
from reportlab.lib.units import inch
from reportlab.lib import colors
from .styles import STYLES
from .components import create_table, create_key_value_table, create_badge, create_card, create_dashboard_stat, create_pill
from .assets import get_logo_image
import datetime

def build_header(context):
    story = []
    
    incident_id = context.get('incident_id', 'Unknown')
    verdict = context.get('verdict', 'SAFE')
    
    # SecureMail Logo
    logo = get_logo_image(76, 76)
    
    # Title Block
    title_data = [
        [logo],
        [Paragraph("TECHNICAL FORENSIC AUDIT", STYLES['MainTitle'])],
        [Paragraph("Security Intelligence Investigation Report", STYLES['SubTitle'])]
    ]
    title_table = Table(title_data, colWidths=['*'])
    title_table.setStyle(TableStyle([
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 2),
    ]))
    
    # Override subtitle color for cover
    title_data[2][0].style.textColor = colors.HexColor('#64748B')
    
    story.append(title_table)
    story.append(Spacer(1, 0.4*inch))
    
    return story

def build_executive_summary(context):
    story = [CondPageBreak(2.5 * inch)]
    
    # Left side: Text Summary
    summary = context.get('executive_summary', 'No summary available.')
    story.append(Paragraph("Executive Summary", STYLES['SectionHeader']))
    story.append(Paragraph(summary, STYLES['BodyTextCustom']))
    story.append(Spacer(1, 0.3*inch))
    
    # Risk Summary Cards
    score = context.get('risk_score', 0)
    verdict = context.get('verdict', 'SAFE')
    confidence = context.get('confidence', 0)
    
    v_color = '#ef4444' if verdict == 'PHISHING' else ('#f97316' if verdict == 'SUSPICIOUS' else '#22c55e')
    s_color = '#f97316' # Orange for score
    c_color = '#3b82f6' # Blue for confidence
    sev_color = '#a855f7' # Purple for severity
    
    dashboard_data = [[
        create_dashboard_stat("VERDICT", verdict, value_color=v_color),
        create_dashboard_stat("RISK SCORE", f"{score}", value_color=s_color),
        create_dashboard_stat("CONFIDENCE", f"{confidence}%", value_color=c_color),
        create_dashboard_stat("SEVERITY", "HIGH" if verdict == 'PHISHING' else "LOW", value_color=sev_color)
    ]]
    
    dashboard_table = Table(dashboard_data, colWidths=['*', '*', '*', '*'])
    dashboard_table.setStyle(TableStyle([
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('LEFTPADDING', (0, 0), (-1, -1), 4),
        ('RIGHTPADDING', (0, 0), (-1, -1), 4),
    ]))
    
    story.append(dashboard_table)
    story.append(Spacer(1, 0.4*inch))
    
    # Incident Information Block
    incident_id = context.get('incident_id', 'Unknown')
    info_data_1 = [
        ("Incident ID", f"#{incident_id}"),
        ("Generated Time", datetime.datetime.now().strftime('%Y-%m-%d %H:%M')),
        ("Classification", verdict)
    ]
    info_data_2 = [
        ("Engine Version", "v2.4"),
        ("AI Version", "Gemini-Flash"),
        ("Threat Category", "Email Security")
    ]
    
    col1 = create_card(None, create_key_value_table(info_data_1), bg_color='#f8fafc')
    col2 = create_card(None, create_key_value_table(info_data_2), bg_color='#f8fafc')
    
    incident_table = Table([[col1, col2]], colWidths=['*', '*'])
    incident_table.setStyle(TableStyle([
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('LEFTPADDING', (0, 0), (-1, -1), 6),
        ('RIGHTPADDING', (0, 0), (-1, -1), 6),
    ]))
    
    story.append(Paragraph("Incident Information", STYLES['SectionHeader']))
    story.append(incident_table)
    story.append(Spacer(1, 0.3*inch))
    
    return story

def build_ai_investigation(context):
    story = [CondPageBreak(2 * inch)]
    story.append(Paragraph("AI Investigation Report", STYLES['SectionHeader']))
    
    analyst = context.get('analyst_explanation', 'No analyst explanation available.')
    tech = context.get('technical_analysis', 'No technical analysis available.')
    conf = context.get('confidence_assessment', 'No assessment available.')
    action = context.get('recommended_action', 'N/A')
    
    story.append(Paragraph("Analyst Explanation", STYLES['CardHeader']))
    story.append(Paragraph(str(analyst), STYLES['BodyTextCustom']))
    story.append(Spacer(1, 0.15*inch))
    
    story.append(Paragraph("Technical Analysis", STYLES['CardHeader']))
    story.append(Paragraph(str(tech), STYLES['BodyTextCustom']))
    story.append(Spacer(1, 0.15*inch))
    
    story.append(Paragraph("Confidence Assessment", STYLES['CardHeader']))
    story.append(Paragraph(str(conf), STYLES['BodyTextCustom']))
    story.append(Spacer(1, 0.15*inch))
    
    story.append(Paragraph("Recommended Action", STYLES['CardHeader']))
    story.append(Paragraph(str(action), STYLES['BodyTextBold']))
    
    story.append(Spacer(1, 0.2*inch))
    return story

def build_red_flags(context):
    story = []
    flags = context.get('red_flags', [])
    if flags:
        story.append(CondPageBreak(2 * inch))
        story.append(Paragraph("Red Flags", STYLES['SectionHeader']))
        for flag in flags:
            row = Table([[Paragraph("<font size=16 color='#dc2626'>⚠</font>", STYLES['BodyTextCustom']), Paragraph(flag, STYLES['BodyTextCustom'])]], colWidths=[28, '*'])
            row.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#fef2f2')),
                ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#fecaca')),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('TOPPADDING', (0, 0), (-1, -1), 12),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
                ('LEFTPADDING', (0, 0), (-1, -1), 16),
            ]))
            story.append(row)
            story.append(Spacer(1, 0.1*inch))
        story.append(Spacer(1, 0.15*inch))
    return story

def build_threat_indicators(context):
    story = [CondPageBreak(2 * inch)]
    
    # 2-column layout for Sender Intel and Threat Indicators
    trusted = "Verified" if context.get('trusted_sender') else "Unverified"
    rep = context.get('sender_reputation', 0)
    
    sender_data = [
        ("Domain", context.get('sender_email', '').split('@')[-1] if '@' in context.get('sender_email', '') else context.get('sender_email', '')),
        ("Status", trusted),
        ("Reputation", f"{rep}/100")
    ]
    
    story.append(Paragraph("Sender Intelligence", STYLES['SectionHeader']))
    
    intel_table = Table([
        [
            create_card("DOMAIN", Paragraph(sender_data[0][1], STYLES['BodyTextBold'])),
            create_card("STATUS", Paragraph(sender_data[1][1], STYLES['BodyTextBold'])),
            create_card("REPUTATION", Paragraph(sender_data[2][1], STYLES['BodyTextBold']))
        ]
    ], colWidths=['*', '*', '*'])
    
    intel_table.setStyle(TableStyle([
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('LEFTPADDING', (0, 0), (-1, -1), 4),
        ('RIGHTPADDING', (0, 0), (-1, -1), 4),
    ]))
    
    story.append(intel_table)
    story.append(Spacer(1, 0.2*inch))
    
    indicators = context.get('threat_indicators', [])
    story.append(Paragraph("Threat Indicators", STYLES['CardHeader']))
    if not indicators:
        story.append(Paragraph("None Detected", STYLES['BodyTextCustom']))
    else:
        for ind in indicators:
            story.append(Paragraph(f"• {ind}", STYLES['BodyTextCustom']))
            story.append(Spacer(1, 0.05*inch))
            
    story.append(Spacer(1, 0.15*inch))
    
    # ML Metrics and Trigger phrases
    ml_data = [[
        create_dashboard_stat("COMPLEXITY", str(context.get('complexity_score', 'N/A'))),
        create_dashboard_stat("ENTROPY", str(context.get('entropy_score', 'N/A')))
    ]]
    ml_table = Table(ml_data, colWidths=['*', '*'])
    ml_table.setStyle(TableStyle([('VALIGN', (0, 0), (-1, -1), 'TOP'), ('LEFTPADDING', (0, 0), (-1, -1), 5), ('RIGHTPADDING', (0, 0), (-1, -1), 5)]))
    
    story.append(Paragraph("ML Engine Metrics", STYLES['CardHeader']))
    story.append(ml_table)
    story.append(Spacer(1, 0.15*inch))
    
    phrases = context.get('trigger_phrases', [])
    story.append(Paragraph("Trigger Phrases", STYLES['CardHeader']))
    if phrases:
        pills = [create_pill(p) for p in phrases]
        for p in pills:
            story.append(p)
            story.append(Spacer(1, 0.02*inch))
    else:
        story.append(Paragraph("No suspicious phrases detected.", STYLES['BodyTextCustom']))
        
    story.append(Spacer(1, 0.15*inch))
    return story

def build_iocs_and_auth(context):
    story = [CondPageBreak(2 * inch)]
    story.append(Paragraph("IOCs & Authentication", STYLES['SectionHeader']))
    
    auth_data = [
        ("SPF", create_badge("PASS" if context.get('spf_pass') else "FAIL", "pass" if context.get('spf_pass') else "fail")),
        ("DKIM", create_badge("PASS" if context.get('dkim_pass') else "FAIL", "pass" if context.get('dkim_pass') else "fail")),
        ("DMARC", create_badge("PASS" if context.get('dmarc_pass') else "FAIL", "pass" if context.get('dmarc_pass') else "fail")),
    ]
    
    auth_card = create_card("Authentication Status", create_key_value_table(auth_data))
    story.append(auth_card)
    story.append(Spacer(1, 0.15*inch))
    
    urls = context.get('links', [])
    if urls:
        story.append(Paragraph("Indicators of Compromise", STYLES['CardHeader']))
        
        for link in urls:
            url_str = link.get('url', '')
            threat = link.get('threat_type', 'SAFE')
            story.append(Paragraph(f"URL: {url_str} - Status: {threat}", STYLES['BodyTextCustom']))
            story.append(Spacer(1, 0.05*inch))
            
    story.append(Spacer(1, 0.2*inch))
    return story

def build_email_metadata(context):
    story = [CondPageBreak(1.5 * inch)]
    story.append(Paragraph("Email Metadata", STYLES['SectionHeader']))
    
    metadata = [
        ("Subject", context.get('subject', 'N/A')),
        ("Sender", context.get('sender_display', 'N/A')),
        ("Date", context.get('date', 'N/A')),
        ("Message-ID", context.get('incident_id', 'N/A'))
    ]
    
    story.append(create_key_value_table(metadata))
    story.append(Spacer(1, 0.2*inch))
    return story

def build_original_content(context):
    story = [CondPageBreak(1.5 * inch)]
    story.append(Paragraph("Original Digital Evidence", STYLES['SectionHeader']))
    
    raw_content = context.get('original_content', 'N/A')
    if len(raw_content) > 10000:
        raw_content = raw_content[:10000] + "\n...[TRUNCATED]"
        
    raw_content = raw_content.replace('<', '&lt;').replace('>', '&gt;').replace('\n', '<br/>').replace(' ', '&nbsp;')
    
    story.append(Paragraph(raw_content, STYLES['ForensicMonospace']))
    story.append(Spacer(1, 0.4*inch))
    
    # Forensic Appendix
    appendix_data = [
        ("Report Integrity", create_badge("VALID", "pass")),
        ("Generated By", "SecureMail Local Intelligence Engine"),
        ("Classification (TLP)", "AMBER"),
        ("Report Version", "1.0"),
        ("Engine Version", "v2.4"),
        ("Generated Timestamp", datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')),
        ("Analysis Status", "Completed Successfully"),
        ("Document Hash", "N/A")
    ]
    
    appendix_card = create_card(None, create_key_value_table(appendix_data), bg_color='#f8fafc')
    
    appendix_flowables = [
        Paragraph("Forensic Appendix", STYLES['CardHeader']),
        appendix_card
    ]
    
    story.append(KeepTogether(appendix_flowables))
    story.append(Spacer(1, 0.2*inch))
    
    return story

from .components import create_table, create_key_value_table, create_badge, create_card, create_dashboard_stat, create_pill, create_timeline_flow

def build_timeline(context):
    story = [CondPageBreak(2.5 * inch)]
    
    verdict = context.get('verdict', 'SAFE')
    v_color = '#16a34a' if verdict == 'SAFE' else ('#dc2626' if verdict == 'PHISHING' else '#ea580c')
    
    timeline_steps = [
        ("Email Received & Parsed", '#94a3b8'),
        ("ML Detection Engine", '#3b82f6'),
        ("Threat Analysis & Reputation Check", '#3b82f6'),
        ("AI Investigation & Explanation", '#3b82f6'),
        (f"Final Verdict Issued: {verdict}", v_color)
    ]
    
    timeline_flowable = create_timeline_flow(timeline_steps)
    story.append(Paragraph("Investigation Timeline", STYLES['SectionHeader']))
    story.append(Spacer(1, 0.1*inch))
    story.append(timeline_flowable)
    story.append(Spacer(1, 0.3*inch))
    
    return story
