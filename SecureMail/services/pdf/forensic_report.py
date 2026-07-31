import os
from io import BytesIO
from reportlab.platypus import SimpleDocTemplate
from .paginator import ReportPaginator
from .sections import (
    build_header,
    build_overview,
    build_executive_summary,
    build_risk_breakdown,
    build_authentication,
    build_sender_intelligence,
    build_header_analysis,
    build_url_investigation,
    build_ml_assessment,
    build_attachments_analysis,
    build_investigation_timeline
)

class ForensicPDFReport:
    def __init__(self, context):
        self.context = context
        
    def generate(self, output_path=None):
        """
        Generates the PDF report. 
        If output_path is provided, writes to file.
        Otherwise, returns a BytesIO object with the PDF content.
        """
        buffer = BytesIO() if output_path is None else output_path
        
        doc = ReportPaginator(buffer, context=self.context)
        
        story = []
        
        # Build document structure
        story.extend(build_header(self.context))
        story.extend(build_overview(self.context))
        story.extend(build_executive_summary(self.context))
        story.extend(build_risk_breakdown(self.context))
        story.extend(build_authentication(self.context))
        story.extend(build_sender_intelligence(self.context))
        story.extend(build_header_analysis(self.context))
        story.extend(build_url_investigation(self.context))
        story.extend(build_ml_assessment(self.context))
        story.extend(build_attachments_analysis(self.context))
        story.extend(build_investigation_timeline(self.context))
        
        doc.build(story)
        
        if output_path is None:
            buffer.seek(0)
            return buffer.getvalue()
            
        return output_path
