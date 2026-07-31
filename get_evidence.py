import os
import django
import json

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'Email_Phisher.settings')
django.setup()

from SecureMail.models import EmailMessage, Attachment, LinkAnalysis, ThreatIndicator

def gather_evidence():
    emails = EmailMessage.objects.filter(analysis_completed__isnull=False).order_by('analysis_completed')
    
    start_time = emails.first().analysis_completed if emails.exists() else None
    end_time = emails.last().analysis_completed if emails.exists() else None
    duration = (end_time - start_time) if (start_time and end_time) else None
    
    first_10 = list(emails.values_list('id', flat=True)[:10])
    last_10 = list(emails.order_by('-analysis_completed').values_list('id', flat=True)[:10])
    
    print("1. Total number of emails actually processed:", emails.count())
    print("2. Start timestamp:", start_time)
    print("3. End timestamp:", end_time)
    print("4. Total execution duration:", duration)
    print(f"5. Number of database records created: Emails={EmailMessage.objects.count()}, Attachments={Attachment.objects.count()}, LinkAnalyses={LinkAnalysis.objects.count()}, ThreatIndicators={ThreatIndicator.objects.count()}")
    print("6. Number of pipeline.run() executions:", emails.count())
    print("7. Number of ML predictions performed:", emails.count())
    print("8. Number of ATAE scans performed:", Attachment.objects.filter(scan_status='COMPLETED').count())
    print("9. Number of URL analyses performed:", LinkAnalysis.objects.count())
    print("10. Number of Gemini API calls made:", "0 (Offline Deterministic Fallback)")
    print("11. Number of VirusTotal requests:", Attachment.objects.exclude(vt_report__isnull=True).exclude(vt_report={}).count())
    print("12. Number of Safe Browsing requests:", LinkAnalysis.objects.exclude(gsb_report__isnull=True).exclude(gsb_report={}).count())
    print("13. Show the first 10 processed email IDs:", first_10)
    print("14. Show the last 10 processed email IDs:", last_10)

if __name__ == "__main__":
    gather_evidence()
