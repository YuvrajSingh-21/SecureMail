import datetime
from reportlab.platypus import BaseDocTemplate, PageTemplate, Frame
from reportlab.lib.units import inch
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from .assets import get_logo_path_str

class ReportPaginator(BaseDocTemplate):
    def __init__(self, filename, context=None, **kw):
        super().__init__(filename, pagesize=letter, **kw)
        self.context = context or {}
        
        # Adjust margins to leave room for canvas header
        self.topMargin = 1.0 * inch
        
        frame = Frame(self.leftMargin, self.bottomMargin, self.width, self.height, id='normal')
        template = PageTemplate(id='test', frames=frame, onPage=self._header_footer)
        self.addPageTemplates([template])
        
    def _header_footer(self, canvas, doc):
        canvas.saveState()
        
        # Draw Header on pages > 1
        if doc.page > 1:
            logo_path = get_logo_path_str()
            incident_id = self.context.get('incident_id', 'Unknown')
            
            canvas.setFont('Helvetica-Bold', 10)
            canvas.setFillColor(colors.HexColor('#1f2937'))
            
            # Left: Logo + Report Name
            if logo_path:
                canvas.drawImage(logo_path, doc.leftMargin, doc.pagesize[1] - 0.78 * inch, width=20, height=20, preserveAspectRatio=True, mask='auto')
                canvas.drawString(doc.leftMargin + 28, doc.pagesize[1] - 0.68 * inch, "Security Intelligence Investigation Report")
            else:
                canvas.drawString(doc.leftMargin, doc.pagesize[1] - 0.68 * inch, "Security Intelligence Investigation Report")
                
            # Right: Incident ID and Page Number
            canvas.setFont('Helvetica', 10)
            canvas.setFillColor(colors.HexColor('#6b7280'))
            right_text = f"Incident #{incident_id} | Page {doc.page}"
            canvas.drawRightString(doc.pagesize[0] - doc.rightMargin, doc.pagesize[1] - 0.68 * inch, right_text)
            
            # Header line
            canvas.setStrokeColor(colors.HexColor('#e5e7eb'))
            canvas.line(doc.leftMargin, doc.pagesize[1] - 0.85 * inch, doc.pagesize[0] - doc.rightMargin, doc.pagesize[1] - 0.85 * inch)
            
        # Draw a line above the footer
        canvas.setStrokeColor(colors.HexColor('#e5e7eb'))
        canvas.line(doc.leftMargin, doc.bottomMargin - 0.2 * inch, doc.pagesize[0] - doc.rightMargin, doc.bottomMargin - 0.2 * inch)
        
        canvas.setFont('Helvetica-Bold', 8)
        canvas.setFillColor(colors.HexColor('#64748B'))
        
        # Left side: Branding
        branding = "SecuraMail Threat Intelligence Platform"
        canvas.drawString(doc.leftMargin, doc.bottomMargin - 0.4 * inch, branding)
        
        # Center left: TLP
        tlp = "Classification (TLP): AMBER"
        canvas.drawString(doc.leftMargin + 2.5 * inch, doc.bottomMargin - 0.4 * inch, tlp)
        
        # Center right: Generated Date
        timestamp = f"Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')}"
        canvas.drawString(doc.leftMargin + 4.5 * inch, doc.bottomMargin - 0.4 * inch, timestamp)
        
        # Right: Page X / Y
        page_num = f"Page {doc.page}"
        canvas.drawRightString(doc.pagesize[0] - doc.rightMargin, doc.bottomMargin - 0.4 * inch, f"{page_num} | Confidential")
        
        canvas.restoreState()
