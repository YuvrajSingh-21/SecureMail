from reportlab.platypus import Paragraph, Table, TableStyle, Spacer, KeepTogether
from reportlab.lib import colors
from reportlab.lib.units import inch
from .styles import STYLES

def create_table(data, col_widths=None, is_header_first_row=True):
    table = Table(data, colWidths=col_widths)
    
    table_style = [
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('LINEBELOW', (0, 0), (-1, -1), 1, colors.HexColor('#f3f4f6')),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('LEFTPADDING', (0, 0), (-1, -1), 8),
        ('RIGHTPADDING', (0, 0), (-1, -1), 8),
    ]
    
    if is_header_first_row:
        table_style.extend([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#f8fafc')),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.HexColor('#6b7280')),
            ('LINEBELOW', (0, 0), (-1, 0), 1, colors.HexColor('#e5e7eb')),
        ])
        
    table.setStyle(TableStyle(table_style))
    return table

def create_card(title, content_flowables, bg_color='#ffffff', border_color='#e5e7eb'):
    # A card is just a table with one column, where the first cell is the header (if present)
    data = []
    if title:
        data.append([Paragraph(title, STYLES['CardHeader'])])
    
    # We can nest flowables in table cells.
    if isinstance(content_flowables, list):
        # We can put a nested table or just stack them if we wrap them in a KeepTogether or another Table
        # But ReportLab Table allows lists of flowables in cells.
        data.append([content_flowables])
    else:
        data.append([[content_flowables]])
        
    table = Table(data, colWidths=['*'])
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor(bg_color)),
        ('BOX', (0, 0), (-1, -1), 1, colors.HexColor(border_color)),
        ('LEFTPADDING', (0, 0), (-1, -1), 12),
        ('RIGHTPADDING', (0, 0), (-1, -1), 12),
        ('TOPPADDING', (0, 0), (-1, -1), 12),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
    ]))
    return table

def create_dashboard_stat(label, value, value_color='#111827'):
    data = [
        [Paragraph(label, STYLES['DashboardLabel'])],
        [Paragraph(str(value), STYLES['DashboardValue'])]
    ]
    
    # Override text color dynamically if needed
    if value_color != '#111827':
        # Create temporary style for colored value
        from copy import deepcopy
        val_style = deepcopy(STYLES['DashboardValue'])
        val_style.textColor = colors.HexColor(value_color)
        data[1][0] = Paragraph(str(value), val_style)

    table = Table(data, colWidths=['*'])
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#ffffff')),
        ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#e5e7eb')),
        ('LEFTPADDING', (0, 0), (-1, -1), 12),
        ('RIGHTPADDING', (0, 0), (-1, -1), 12),
        ('TOPPADDING', (0, 0), (-1, -1), 12),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
    ]))
    return table

def create_badge(text, level):
    style_name = 'BadgeMedium'
    level = str(level).lower()
    if level in ['high', 'critical', 'fail', 'malicious', 'phishing']:
        style_name = 'BadgeHigh'
    elif level in ['low', 'info', 'pass', 'safe', 'verified']:
        style_name = 'BadgeLow'
        
    return Paragraph(str(text), STYLES[style_name])
    
def create_pill(text):
    return Paragraph(str(text), STYLES['Pill'])

from reportlab.graphics.shapes import Drawing, Circle, Line, String, Group
from reportlab.lib.units import inch

def create_timeline_flow(steps):
    # steps is a list of (label, status_color)
    d = Drawing(400, len(steps) * 35 + 10)
    
    y = len(steps) * 35
    for i, (label, color) in enumerate(steps):
        # Draw outer subtle ring
        d.add(Circle(20, y, 9, fillColor=colors.HexColor('#f8fafc'), strokeColor=colors.HexColor(color), strokeWidth=1.5))
        # Draw inner dot
        d.add(Circle(20, y, 4, fillColor=colors.HexColor(color), strokeColor=colors.HexColor(color)))
        
        # Draw connecting line
        if i < len(steps) - 1:
            d.add(Line(20, y - 9, 20, y - 26, strokeColor=colors.HexColor('#cbd5e1'), strokeWidth=2))
            
        # Draw label
        d.add(String(45, y - 4, label, fontName='Helvetica-Bold', fontSize=10.5, fillColor=colors.HexColor('#1e293b')))
        
        y -= 35
        
    return d

def create_key_value_table(kv_pairs):
    data = []
    for k, v in kv_pairs:
        data.append([
            Paragraph(f"<b>{k}</b>", STYLES['BodyTextCustom']),
            Paragraph(str(v), STYLES['BodyTextCustom']) if not isinstance(v, (list, Paragraph)) else v
        ])
    
    # We want this to look like a clean modern table without borders
    table = Table(data, colWidths=[120, '*'])
    table.setStyle(TableStyle([
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('LINEBELOW', (0, 0), (-1, -1), 1, colors.HexColor('#f3f4f6')),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
    ]))
    return table
