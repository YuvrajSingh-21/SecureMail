import os
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT

def get_report_styles():
    styles = getSampleStyleSheet()
    
    # Custom colors
    # Blue branding, Red critical, Orange warning, Green pass, Gray metadata
    color_bg_gray = colors.HexColor('#f8fafc')
    color_text_gray = colors.HexColor('#4b5563')
    color_blue = colors.HexColor('#1e40af')
    color_red = colors.HexColor('#dc2626')
    color_orange = colors.HexColor('#ea580c')
    color_green = colors.HexColor('#16a34a')
    
    # Custom styles
    styles.add(ParagraphStyle(
        name='MainTitle',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=26,
        textColor=colors.HexColor('#0f172a'),  # Slate 900
        alignment=TA_LEFT,
        spaceAfter=6,
        textTransform='uppercase'
    ))
    
    styles.add(ParagraphStyle(
        name='SubTitle',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=13,
        textColor=colors.HexColor('#2563eb'),  # Primary Blue
        spaceAfter=15,
        textTransform='uppercase'
    ))

    styles.add(ParagraphStyle(
        name='SectionHeader',
        parent=styles['Heading3'],
        fontName='Helvetica-Bold',
        fontSize=12,
        textColor=colors.white,
        backColor=colors.HexColor('#1e40af'), # Deep Blue
        spaceAfter=15,
        spaceBefore=24,
        borderPadding=8,
        textTransform='uppercase',
        keepWithNext=True
    ))

    styles.add(ParagraphStyle(
        name='CardHeader',
        parent=styles['Heading4'],
        fontName='Helvetica-Bold',
        fontSize=11,
        textColor=colors.HexColor('#475569'),  # Slate 600
        spaceAfter=8,
        spaceBefore=10,
        textTransform='uppercase',
        keepWithNext=True
    ))

    styles.add(ParagraphStyle(
        name='BodyTextCustom',
        parent=styles['BodyText'],
        fontName='Helvetica',
        fontSize=10.5,
        textColor=colors.HexColor('#334155'),  # Slate 700
        spaceAfter=8,
        leading=15
    ))
    
    styles.add(ParagraphStyle(
        name='BodyTextBold',
        parent=styles['BodyTextCustom'],
        fontName='Helvetica-Bold',
    ))
    
    styles.add(ParagraphStyle(
        name='Monospace',
        parent=styles['BodyText'],
        fontName='Courier',
        fontSize=8,
        textColor=colors.HexColor('#1f2937'),
        leading=10
    ))
    
    styles.add(ParagraphStyle(
        name='ForensicMonospace',
        parent=styles['Monospace'],
        backColor=colors.HexColor('#f1f5f9'),
        borderPadding=12,
        borderColor=colors.HexColor('#94a3b8'),
        borderWidth=1,
        textColor=colors.HexColor('#334155'),
        leading=12
    ))

    styles.add(ParagraphStyle(
        name='DashboardValue',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=14,
        textColor=colors.HexColor('#111827'),
        alignment=TA_LEFT,
        spaceAfter=2
    ))
    
    styles.add(ParagraphStyle(
        name='DashboardLabel',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=8,
        textColor=colors.HexColor('#9ca3af'),
        alignment=TA_LEFT,
        textTransform='uppercase'
    ))

    # Badges
    styles.add(ParagraphStyle(
        name='BadgeHigh',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=10,
        textColor=colors.white,
        backColor=color_red,
        borderPadding=4,
        alignment=TA_CENTER
    ))
    
    styles.add(ParagraphStyle(
        name='BadgeMedium',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=10,
        textColor=colors.white,
        backColor=color_orange,
        borderPadding=4,
        alignment=TA_CENTER
    ))

    styles.add(ParagraphStyle(
        name='BadgeLow',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=10,
        textColor=colors.white,
        backColor=color_green,
        borderPadding=4,
        alignment=TA_CENTER
    ))
    
    styles.add(ParagraphStyle(
        name='Pill',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=9,
        textColor=color_red,
        backColor=colors.HexColor('#fef2f2'),
        borderPadding=4,
        alignment=TA_CENTER
    ))

    return styles

STYLES = get_report_styles()
