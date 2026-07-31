from reportlab.platypus import Paragraph, Spacer, KeepTogether, Table, TableStyle, CondPageBreak
from reportlab.lib.units import inch
from reportlab.lib import colors
from .styles import STYLES
from .components import create_table, create_key_value_table, create_badge, create_card, create_dashboard_stat, create_pill, create_timeline_flow
from .assets import get_logo_image
import datetime

def build_header(context):
    story = []
    
    # SecureMail Logo
    logo = get_logo_image(76, 76)
    
    # Title Block
    title_data = [
        [logo],
        [Paragraph("FULL TECHNICAL AUDIT", STYLES['MainTitle'])],
        [Paragraph("Security Intelligence Investigation Report", STYLES['SubTitle'])]
    ]
    title_table = Table(title_data, colWidths=['*'])
    title_table.setStyle(TableStyle([
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 2),
    ]))
    
    title_data[2][0].style.textColor = colors.HexColor('#64748B')
    
    story.append(title_table)
    story.append(Spacer(1, 0.4*inch))
    return story

def build_overview(context):
    story = [CondPageBreak(2 * inch)]
    story.append(Paragraph("1. Overview", STYLES['SectionHeader']))
    
    verdict = context.get('verdict', 'SAFE')
    score = context.get('risk_score', 0)
    confidence = context.get('confidence', 0)
    threat_category = context.get('threat_category', 'Email Security')
    status = context.get('investigation_status', 'Completed')
    
    v_color = '#ef4444' if verdict == 'PHISHING' else ('#f97316' if verdict == 'SUSPICIOUS' else '#22c55e')
    s_color = '#f97316' # Orange for score
    c_color = '#3b82f6' # Blue for confidence
    
    dashboard_data = [[
        create_dashboard_stat("OVERALL VERDICT", verdict, value_color=v_color),
        create_dashboard_stat("RISK SCORE", f"{score}/100", value_color=s_color),
        create_dashboard_stat("CONFIDENCE", f"{confidence}%", value_color=c_color),
    ]]
    
    dashboard_table = Table(dashboard_data, colWidths=['*', '*', '*'])
    dashboard_table.setStyle(TableStyle([
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('LEFTPADDING', (0, 0), (-1, -1), 4),
        ('RIGHTPADDING', (0, 0), (-1, -1), 4),
    ]))
    
    story.append(dashboard_table)
    story.append(Spacer(1, 0.2*inch))
    
    metadata_data = [
        ("Threat Category", threat_category),
        ("Investigation Status", status)
    ]
    story.append(create_card(None, create_key_value_table(metadata_data), bg_color='#f8fafc'))
    story.append(Spacer(1, 0.3*inch))
    
    return story

def build_executive_summary(context):
    story = [CondPageBreak(2.5 * inch)]
    story.append(Paragraph("2. Executive Summary", STYLES['SectionHeader']))
    
    ai_summary = context.get('ai_summary', 'No summary available.')
    tech = context.get('technical_explanation', 'No technical explanation available.')
    action = context.get('recommended_action', 'N/A')
    
    story.append(Paragraph("AI Summary from Gemini", STYLES['CardHeader']))
    story.append(Paragraph(str(ai_summary), STYLES['BodyTextCustom']))
    story.append(Spacer(1, 0.15*inch))
    
    story.append(Paragraph("Technical Explanation", STYLES['CardHeader']))
    story.append(Paragraph(str(tech), STYLES['BodyTextCustom']))
    story.append(Spacer(1, 0.15*inch))
    
    story.append(Paragraph("Recommended Action", STYLES['CardHeader']))
    story.append(Paragraph(str(action), STYLES['BodyTextBold']))
    
    story.append(Spacer(1, 0.3*inch))
    return story

def build_risk_breakdown(context):
    story = [CondPageBreak(2 * inch)]
    story.append(Paragraph("3. Risk Breakdown", STYLES['SectionHeader']))
    
    breakdown = context.get('risk_breakdown', [])
    if breakdown:
        data = [["Factor", "Score"]]
        for factor, score in breakdown:
            data.append([Paragraph(str(factor), STYLES['BodyTextCustom']), Paragraph(f"+{score}", STYLES['BodyTextBold'])])
            
        data.append([Paragraph("Total Risk", STYLES['BodyTextBold']), Paragraph(str(context.get('risk_score', 0)), STYLES['BodyTextBold'])])
        
        table = create_table(data, col_widths=['*', 100])
        story.append(table)
    else:
        story.append(Paragraph("No risk breakdown available.", STYLES['BodyTextCustom']))
        
    story.append(Spacer(1, 0.3*inch))
    return story

def build_authentication(context):
    story = [CondPageBreak(1.5 * inch)]
    story.append(Paragraph("4. Authentication", STYLES['SectionHeader']))
    
    auth_data = [
        ("SPF", create_badge("PASS" if context.get('spf_pass') else "FAIL", "pass" if context.get('spf_pass') else "fail")),
        ("DKIM", create_badge("PASS" if context.get('dkim_pass') else "FAIL", "pass" if context.get('dkim_pass') else "fail")),
        ("DMARC", create_badge("PASS" if context.get('dmarc_pass') else "FAIL", "pass" if context.get('dmarc_pass') else "fail")),
    ]
    
    auth_card = create_card(None, create_key_value_table(auth_data))
    story.append(auth_card)
    story.append(Spacer(1, 0.3*inch))
    return story

def build_sender_intelligence(context):
    story = [CondPageBreak(2 * inch)]
    story.append(Paragraph("5. Sender Intelligence", STYLES['SectionHeader']))
    
    sender_data = [
        ("Domain", context.get('sender_domain', 'N/A')),
        ("Display Name", context.get('sender_display', 'N/A')),
        ("Reputation", context.get('sender_reputation', 'N/A')),
        ("Spoofing Detection", context.get('spoofing_detection', 'N/A'))
    ]
    
    story.append(create_card(None, create_key_value_table(sender_data)))
    story.append(Spacer(1, 0.3*inch))
    return story

def build_header_analysis(context):
    story = [CondPageBreak(2 * inch)]
    story.append(Paragraph("6. Header Analysis", STYLES['SectionHeader']))
    
    header_data = [
        ("Message ID", context.get('message_id', 'N/A')),
        ("Return Path", context.get('return_path', 'N/A')),
        ("Originating IP", context.get('originating_ip', 'N/A')),
    ]
    
    story.append(create_card(None, create_key_value_table(header_data)))
    story.append(Spacer(1, 0.2*inch))
    
    suspicious_headers = context.get('suspicious_headers', [])
    story.append(Paragraph("Suspicious Headers", STYLES['CardHeader']))
    if suspicious_headers:
        for header in suspicious_headers:
            story.append(Paragraph(f"• {header}", STYLES['BodyTextCustom']))
            story.append(Spacer(1, 0.05*inch))
    else:
        story.append(Paragraph("None Detected", STYLES['BodyTextCustom']))
        
    story.append(Spacer(1, 0.3*inch))
    return story

def build_url_investigation(context):
    story = [CondPageBreak(2 * inch)]
    story.append(Paragraph("7. URL Investigation", STYLES['SectionHeader']))
    
    urls = context.get('urls', [])
    if urls:
        data = [["URL", "Safe Browsing", "VirusTotal", "Verdict"]]
        for u in urls:
            url_str = u.get('url', 'N/A')
            sb = u.get('safe_browsing', 'N/A')
            vt = u.get('virustotal', 'N/A')
            verdict = u.get('verdict', 'N/A')
            
            data.append([
                Paragraph(url_str, STYLES['BodyTextCustom']),
                Paragraph(sb, STYLES['BodyTextCustom']),
                Paragraph(vt, STYLES['BodyTextCustom']),
                create_badge(verdict, verdict)
            ])
            
        table = create_table(data, col_widths=['*', 80, 80, 70])
        story.append(table)
    else:
        story.append(Paragraph("No URLs detected in the email.", STYLES['BodyTextCustom']))
        
    story.append(Spacer(1, 0.3*inch))
    return story

def build_ml_assessment(context):
    story = [CondPageBreak(2 * inch)]
    story.append(Paragraph("8. Machine Learning Assessment", STYLES['SectionHeader']))
    
    factors = context.get('detection_reasoning', [])
    story.append(Paragraph("Detection Reasoning", STYLES['CardHeader']))
    if factors:
        for factor in factors:
            story.append(Paragraph(f"• {factor}", STYLES['BodyTextCustom']))
            story.append(Spacer(1, 0.05*inch))
    else:
        story.append(Paragraph("N/A", STYLES['BodyTextCustom']))
        
    story.append(Spacer(1, 0.2*inch))
    
    phrases = context.get('suspicious_phrases', [])
    story.append(Paragraph("Suspicious Phrases", STYLES['CardHeader']))
    if phrases:
        pills = [create_pill(p) for p in phrases]
        for p in pills:
            story.append(p)
            story.append(Spacer(1, 0.02*inch))
    else:
        story.append(Paragraph("No suspicious phrases detected.", STYLES['BodyTextCustom']))
        
    story.append(Spacer(1, 0.3*inch))
    return story

def build_attachments_analysis(context):
    story = [CondPageBreak(2 * inch)]
    story.append(Paragraph("9. Attachments Security Analysis", STYLES['SectionHeader']))
    
    attachments = context.get('attachments', [])
    if attachments:
        for a in attachments:
            kv_data = []
            kv_data.append(("Filename", a.get('filename', 'N/A')))
            kv_data.append(("File Type", a.get('extension', 'UNKNOWN')))
            
            if a.get('size'):
                kv_data.append(("File Size", a.get('size')))
            if a.get('sha256'):
                kv_data.append(("SHA-256", a.get('sha256')))
                
            if a.get('analyzer') and a.get('analyzer') != 'N/A':
                kv_data.append(("Analyzer Used", a.get('analyzer')))
                
            kv_data.append(("Risk Score", f"{a.get('risk_score', '0')}/100"))
            kv_data.append(("Verdict", create_badge(a.get('verdict', 'N/A'), a.get('verdict', 'N/A'))))
            
            card_content = [create_key_value_table(kv_data)]
            
            findings = a.get('findings', [])
            if findings:
                card_content.append(Spacer(1, 0.15*inch))
                card_content.append(Paragraph("Identified Findings", STYLES['CardHeader']))
                for finding in findings:
                    card_content.append(Paragraph(f"• {finding}", STYLES['BodyTextCustom']))
                    card_content.append(Spacer(1, 0.05*inch))
                    
            if a.get('recommendation'):
                card_content.append(Spacer(1, 0.1*inch))
                card_content.append(Paragraph("Recommendation", STYLES['CardHeader']))
                card_content.append(Paragraph(a.get('recommendation'), STYLES['BodyTextCustom']))
                
            story.append(create_card(None, card_content, bg_color='#f8fafc'))
            story.append(Spacer(1, 0.3*inch))
            
    else:
        story.append(Paragraph("No attachments found.", STYLES['BodyTextCustom']))
        story.append(Spacer(1, 0.3*inch))
        
    return story

def build_investigation_timeline(context):
    story = [CondPageBreak(2.5 * inch)]
    story.append(Paragraph("10. Investigation Timeline", STYLES['SectionHeader']))
    
    timeline = context.get('timeline', [])
    if timeline:
        timeline_flowable = create_timeline_flow(timeline)
        story.append(timeline_flowable)
    else:
        story.append(Paragraph("No timeline available.", STYLES['BodyTextCustom']))
        
    story.append(Spacer(1, 0.3*inch))
    
    return story
