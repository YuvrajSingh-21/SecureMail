import os
from io import BytesIO
from reportlab.platypus import SimpleDocTemplate
from .paginator import ReportPaginator
from .sections import (
    build_header,
    build_executive_summary,
    build_ai_investigation,
    build_red_flags,
    build_threat_indicators,
    build_iocs_and_auth,
    build_email_metadata,
    build_original_content,
    build_timeline
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
        story.extend(build_executive_summary(self.context))
        story.extend(build_ai_investigation(self.context))
        story.extend(build_red_flags(self.context))
        story.extend(build_threat_indicators(self.context))
        story.extend(build_iocs_and_auth(self.context))
        story.extend(build_timeline(self.context))
        story.extend(build_email_metadata(self.context))
        story.extend(build_original_content(self.context))
        
        doc.build(story)
        
        if output_path is None:
            buffer.seek(0)
            return buffer.getvalue()
            
        return output_path
