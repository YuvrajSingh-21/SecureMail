from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import login, authenticate, logout
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.core.paginator import Paginator
from .services.business_logic import EmailService, ProfileService
from .services.sync_manager import SyncManager
from .models import EmailMessage, EmailReport, ConnectedAccount

@login_required(login_url='login')
def sync_gmail(request):
    full_sync = request.GET.get('all') == 'true'
    is_auto = request.GET.get('auto') == '1'
    
    if is_auto:
        from .models import SyncJob
        # Prevent starting a new sync if one is already running
        if SyncJob.objects.filter(user=request.user, status='RUNNING').exists():
            from django.http import JsonResponse
            return JsonResponse({'status': 'already_running'})

    manager = SyncManager(request.user)
    job = manager.start_sync(full_sync=full_sync)
    
    if is_auto:
        from django.http import JsonResponse
        return JsonResponse({'status': 'started' if job else 'failed'})
    
    if job:
        sync_type = "Full" if full_sync else "Latest"
        messages.success(request, f"{sync_type} sync started. Your inbox is being updated in the background.")
    else:
        messages.error(request, "Failed to start synchronization. Ensure your Gmail is connected.")
        
    return redirect('inbox')

@login_required(login_url='login')
def dashboard(request):
    emails = EmailMessage.objects.filter(user=request.user)
    
    # Updated stats to handle normalized categories
    stats = {
        'total': emails.count(),
        'safe': emails.filter(category__in=['SAFE', 'PROMOTIONAL', 'NEWSLETTER', 'SOCIAL']).count(),
        'suspicious': emails.filter(category='SUSPICIOUS').count(),
        'dangerous': emails.filter(category='PHISHING').count(),
        'security_score': request.user.profile.security_score,
    }
    
    # Get weekly trend (last 7 days)
    from django.utils import timezone
    from datetime import timedelta
    trend_data = []
    for i in range(7):
        day = (timezone.now() - timedelta(days=6-i)).date()
        count = emails.filter(timestamp__date=day, ml_label='PHISHING').count()
        # Scale to percentage for height
        scaled_count = min(100, (count / 10 * 100)) if count > 0 else 0
        trend_data.append(scaled_count)
    
    # Calculate score offset for Dashboard SVG (r=100, circumference approx 628.3)
    stats['score_offset'] = 628.3 * (1 - stats['security_score'] / 100)
    
    return render(request, 'dashboard.html', {
        'stats': stats,
        'trend_data': trend_data
    })

@login_required(login_url='login')
def inbox(request, folder=None):
    if request.method == 'POST':
        action = request.POST.get('action')
        email_ids = request.POST.getlist('email_ids')
        if action == 'empty_trash':
            trash_emails = EmailMessage.objects.filter(user=request.user, in_trash=True)
            count = trash_emails.count()
            for msg in trash_emails:
                for att in msg.attachments.all():
                    if att.file:
                        try:
                            att.file.delete(save=False)
                        except: pass
            trash_emails.delete()
            msg_text = f'Permanently deleted {count} emails from Trash.'
            messages.success(request, msg_text)
        elif email_ids:
            if action == 'delete':
                if folder == 'trash':
                    # Delete Forever if in Trash
                    to_delete = EmailMessage.objects.filter(id__in=email_ids, user=request.user, in_trash=True)
                    count = to_delete.count()
                    for msg in to_delete:
                        for att in msg.attachments.all():
                            if att.file:
                                try:
                                    att.file.delete(save=False)
                                except: pass
                    to_delete.delete()
                    msg_text = f'Permanently deleted {count} emails.'
                    messages.success(request, msg_text)
                else:
                    EmailMessage.objects.filter(id__in=email_ids, user=request.user).update(in_trash=True)
                    msg_text = f'Moved {len(email_ids)} emails to trash.'
                    messages.success(request, msg_text)
            elif action == 'delete_forever':
                to_delete = EmailMessage.objects.filter(id__in=email_ids, user=request.user)
                count = to_delete.count()
                for msg in to_delete:
                    for att in msg.attachments.all():
                        if att.file:
                            try:
                                att.file.delete(save=False)
                            except: pass
                to_delete.delete()
                msg_text = f'Permanently deleted {count} emails.'
                messages.success(request, msg_text)
            elif action == 'restore':
                EmailMessage.objects.filter(id__in=email_ids, user=request.user).update(in_trash=False, folder='INBOX')
                msg_text = f'Restored {len(email_ids)} emails to Inbox.'
                messages.success(request, msg_text)
            elif action == 'archive':
                EmailMessage.objects.filter(id__in=email_ids, user=request.user).update(folder='ARCHIVE', in_trash=False)
                msg_text = f'Archived {len(email_ids)} emails.'
                messages.success(request, msg_text)
            elif action == 'unarchive':
                EmailMessage.objects.filter(id__in=email_ids, user=request.user).update(folder='INBOX', in_trash=False)
                msg_text = f'Moved {len(email_ids)} emails to Inbox.'
                messages.success(request, msg_text)
            elif action == 'mark_read':
                EmailMessage.objects.filter(id__in=email_ids, user=request.user).update(unread=False)
                msg_text = f'Marked {len(email_ids)} emails as read.'
                messages.success(request, msg_text)
            elif action == 'mark_unread':
                EmailMessage.objects.filter(id__in=email_ids, user=request.user).update(unread=True)
                msg_text = f'Marked {len(email_ids)} emails as unread.'
                messages.success(request, msg_text)
        
        if request.headers.get('x-requested-with') == 'XMLHttpRequest' or request.headers.get('accept') == 'application/json':
            from django.http import JsonResponse
            from SecureMail.context_processors import sidebar_stats
            counts = sidebar_stats(request)
            return JsonResponse({
                'success': True, 
                'status': 'ok',
                'message': locals().get('msg_text', 'Action completed successfully.'),
                'counts': counts
            })
            
        return redirect(request.META.get('HTTP_REFERER', 'inbox'))

    query = request.GET.get('q')
    msg_filter = request.GET.get('filter')
    emails = EmailMessage.objects.filter(user=request.user).select_related('analysis')
    
    if msg_filter == 'unread':
        emails = emails.filter(unread=True)
    elif msg_filter == 'read':
        emails = emails.filter(unread=False)
    
    if folder == 'starred':
        emails = emails.filter(starred=True, in_trash=False)
        title = "Starred"
    elif folder == 'trash':
        emails = emails.filter(in_trash=True)
        title = "Trash"
    elif folder == 'important':
        # Mapping 'Important' to specific Gmail labels if stored, or high risk
        emails = emails.filter(ml_label__in=['PHISHING', 'SUSPICIOUS'], in_trash=False)
        title = "Important"
    elif folder == 'drafts':
        emails = emails.filter(folder='DRAFTS', in_trash=False)
        title = "Drafts"
    elif folder == 'sent':
        emails = emails.filter(folder='SENT', in_trash=False)
        title = "Sent"
    elif folder == 'spam':
        emails = emails.filter(folder='SPAM', in_trash=False)
        title = "Spam"
    elif folder == 'suspicious':
        emails = emails.filter(ml_label='SUSPICIOUS', in_trash=False)
        title = "Suspicious"
    elif folder == 'malicious':
        emails = emails.filter(ml_label='PHISHING', in_trash=False)
        title = "Threats"
    elif folder == 'archive':
        emails = emails.filter(folder='ARCHIVE', in_trash=False)
        title = "Archive"
    else:
        emails = emails.filter(folder='INBOX', in_trash=False)
        title = "Inbox"

    if query:
        emails = emails.filter(subject__icontains=query) | emails.filter(sender_email__icontains=query)

    sort_by = request.GET.get('sort', 'newest')
    if sort_by == 'oldest':
        emails = emails.order_by('timestamp')
    elif sort_by == 'risk':
        emails = emails.order_by('-ml_score', '-timestamp')
    else:
        # newest is default
        emails = emails.order_by('-timestamp')
    
    # Pagination
    paginator = Paginator(emails, 50) # 50 per page
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    unread_count = EmailMessage.objects.filter(user=request.user, unread=True, in_trash=False).count()
    
    return render(request, 'inbox.html', {
        'emails': page_obj, 
        'page_obj': page_obj,
        'unread_count': unread_count,
        'current_folder': folder or 'inbox',
        'folder_title': title
    })

@login_required(login_url='login')
def toggle_star(request, id):
    email_service = EmailService()
    email_service.toggle_star(request.user, id)
    return redirect(request.META.get('HTTP_REFERER', 'inbox'))

@login_required(login_url='login')
def delete_email(request, id):
    email = get_object_or_404(EmailMessage, id=id, user=request.user)
    if email.in_trash:
        for att in email.attachments.all():
            if att.file:
                try:
                    att.file.delete(save=False)
                except: pass
        email.delete()
        messages.info(request, "Message permanently deleted.")
    else:
        email.in_trash = True
        email.save()
        messages.info(request, "Message moved to trash.")
    return redirect(request.META.get('HTTP_REFERER', 'inbox'))

@login_required(login_url='login')
def report_false_positive(request, id):
    if request.method == 'POST':
        email = get_object_or_404(EmailMessage, id=id, user=request.user)
        email.ml_label = 'SAFE'
        email.risk_score = 10
        email.ml_score = 10
        email.risk = 'safe'
        email.category = 'SAFE'
        email.save()
        
        updated_state = {}
        if hasattr(email, 'analysis'):
            import copy
            report = copy.deepcopy(email.analysis.detailed_report)
            report['label'] = 'SAFE'
            report['score'] = 10
            report['confidence'] = 100.0
            report['badge_label'] = 'User Verified Safe'
            report['risk_factors'] = []
            report['safe_factors'] = ["Marked as safe by user override.", "Standard validation passed."]
            report['reasons'] = ["User manually verified this email as not malicious."]
            report['explanations'] = [{"type": "user_feedback", "severity": "safe", "message": "✔ User manually verified this email as not malicious"}]
            report['summary'] = "User manually verified this email as not malicious."
            report['feedback_submitted'] = True
            email.analysis.detailed_report = report
            email.analysis.save()
            updated_state = report

        if request.headers.get('x-requested-with') == 'XMLHttpRequest':
            from django.http import JsonResponse
            return JsonResponse({'status': 'ok', 'data': updated_state})
            
        messages.success(request, "Email marked as Safe. ML Model intelligence has been updated.")
        return redirect('email_view', id=id)
    return redirect('inbox')

@login_required(login_url='login')
def report_true_positive(request, id):
    if request.method == 'POST':
        email = get_object_or_404(EmailMessage, id=id, user=request.user)
        email.ml_label = 'PHISHING'
        email.risk_score = 95
        email.ml_score = 95
        email.risk = 'dangerous'
        email.category = 'PHISHING'
        email.save()
        
        updated_state = {}
        if hasattr(email, 'analysis'):
            import copy
            report = copy.deepcopy(email.analysis.detailed_report)
            report['label'] = 'PHISHING'
            report['score'] = 95
            report['confidence'] = 100.0
            report['badge_label'] = 'User Verified Threat'
            report['risk_factors'] = ["Marked as malicious by user override."]
            report['safe_factors'] = []
            report['reasons'] = ["User manually verified this email as malicious."]
            report['explanations'] = [{"type": "user_feedback", "severity": "critical", "message": "⚠ User manually verified this email as malicious"}]
            report['summary'] = "User manually verified this email as malicious."
            report['feedback_submitted'] = True
            email.analysis.detailed_report = report
            email.analysis.save()
            updated_state = report

        if request.headers.get('x-requested-with') == 'XMLHttpRequest':
            from django.http import JsonResponse
            return JsonResponse({'status': 'ok', 'data': updated_state})
            
        messages.success(request, "Email marked as Malicious. ML Model intelligence has been updated.")
        return redirect('email_view', id=id)
    return redirect('inbox')

@login_required(login_url='login')
def email_view(request, id):
    email_service = EmailService()
    email = email_service.get_email_detail(request.user, id)
    
    # Calculate offset for Email View SVG (r=70, circumference approx 439.8)
    # Aligning with user requirement: "Threat Index must equal ml_score"
    score = email.ml_score if email.ml_score is not None else 0
    email.score_offset = 439.8 * (1 - score / 100)
    
    analysis_norm = email_service.get_email_verdict(email)
    features = {}
    if hasattr(email, 'analysis'):
        report = email.analysis.detailed_report
        features = report.get('features', {})
        if not features and 'ml_metadata' in report:
            features = report['ml_metadata'].get('features', {})
        
    # Unified forensic context
    context = email_service.build_forensic_context(email)
    
    forensic = {
        'analysis': email_service.get_email_verdict(email),
        'features': context.get('features', {})
    }
    
    if hasattr(request.user, 'profile') and request.user.profile.block_tracking_pixels:
        if email.html_body:
            import re
            email.html_body = re.sub(r'<img[^>]*width=["\']?[01]["\']?[^>]*height=["\']?[01]["\']?[^>]*>', '', email.html_body, flags=re.IGNORECASE)
            email.html_body = re.sub(r'<img[^>]*height=["\']?[01]["\']?[^>]*width=["\']?[01]["\']?[^>]*>', '', email.html_body, flags=re.IGNORECASE)
            # Also remove images with tracking pixel domains or base64 1x1 if needed, but above covers standard 1x1s
    
    return render(request, 'email-view.html', {'email': email, 'forensic': forensic, 'report_context': context})

from django.http import FileResponse
from .services.pdf.forensic_report import ForensicPDFReport

@login_required(login_url='login')
def export_pdf(request, id):
    email_service = EmailService()
    email = email_service.get_email_detail(request.user, id)
    
    context = email_service.build_forensic_context(email)
    
    report = ForensicPDFReport(context)
    pdf_bytes = report.generate()
    
    from io import BytesIO
    buffer = BytesIO(pdf_bytes)
    return FileResponse(buffer, as_attachment=True, filename=f"Technical_Forensic_Audit_{email.id}.pdf")


from .decorators import rate_limit_view

@login_required(login_url='login')
@rate_limit_view(key='user', rate='10/m')
def compose(request):
    if request.method == 'POST':
        to = request.POST.get('to')
        subject = request.POST.get('subject')
        body = request.POST.get('body')
        
        try:
            account = ConnectedAccount.objects.get(user=request.user)
            from .services.gmail_service import GmailService
            GmailService(account).send_message(to, subject, body)
            messages.success(request, "Email sent successfully via Gmail!")
            return redirect('inbox')
        except Exception as e:
            messages.error(request, f"Failed to send email: {str(e)}")
            
    return render(request, 'compose.html')

@login_required(login_url='login')
def reports(request):
    emails = EmailMessage.objects.filter(user=request.user)
    
    # Updated stats to handle normalized categories
    stats = {
        'total': emails.count(),
        'safe': emails.filter(category__in=['SAFE', 'PROMOTIONAL', 'NEWSLETTER', 'SOCIAL']).count(),
        'suspicious': emails.filter(category='SUSPICIOUS').count(),
        'malicious': emails.filter(category='PHISHING').count(),
        'spam': emails.filter(category='SPAM').count(),
    }
    
    # Get actual top phishing domains
    from django.db.models import Count
    top_domains = EmailMessage.objects.filter(user=request.user, category='PHISHING') \
        .values('sender_email') \
        .annotate(count=Count('id')) \
        .order_by('-count')[:5]
        
    # Formatting domains for the template
    domain_data = []
    for entry in top_domains:
        domain = entry['sender_email'].split('@')[-1]
        domain_data.append({'domain': domain, 'count': entry['count']})
        
    # Get weekly trend (last 7 days)
    from django.utils import timezone
    from datetime import timedelta
    seven_days_ago = timezone.now() - timedelta(days=7)
    trend_emails = EmailMessage.objects.filter(user=request.user, timestamp__gte=seven_days_ago)
    
    # Grouping by day
    trend_data = []
    for i in range(7):
        day = (timezone.now() - timedelta(days=6-i)).date()
        count = trend_emails.filter(timestamp__date=day, ml_label='PHISHING').count()
        # Scale to percentage for height (max 50 for visualization)
        scaled_count = min(100, (count / 10 * 100)) if count > 0 else 0
        trend_data.append(scaled_count)
        
    return render(request, 'reports.html', {
        'stats': stats,
        'top_domains': domain_data,
        'trend_data': trend_data
    })

@login_required(login_url='login')
def settings_view(request):
    if request.method == 'POST':
        is_protected = request.POST.get('is_protected') == 'on'
        alert_threats = request.POST.get('alert_threats') == 'on'
        alert_digest = request.POST.get('alert_digest') == 'on'
        block_tracking_pixels = request.POST.get('block_tracking_pixels') == 'on'
        timezone = request.POST.get('timezone')
        language = request.POST.get('language')
        username = request.POST.get('username')
        display_name = request.POST.get('display_name')
        
        service = ProfileService()
        profile = service.repository.get_by_user(request.user)
        
        if display_name:
            parts = display_name.split(' ', 1)
            request.user.first_name = parts[0]
            request.user.last_name = parts[1] if len(parts) > 1 else ''
            request.user.save()
            messages.success(request, "Display name updated successfully.")

        if timezone:
            profile.timezone = timezone
        if language:
            profile.language = language
            
        profile.is_protected = is_protected
        profile.alert_threats = alert_threats
        profile.alert_digest = alert_digest
        profile.block_tracking_pixels = block_tracking_pixels
        profile.save()
        
        new_username = request.POST.get('username')
        if new_username and new_username != request.user.username:
            from django.contrib.auth.models import User
            if User.objects.filter(username=new_username).exclude(id=request.user.id).exists():
                messages.error(request, "That username is already taken.")
            else:
                request.user.username = new_username
                request.user.save()
                messages.success(request, "Username updated successfully.")
        
        if not messages.get_messages(request):
            messages.success(request, "Settings updated successfully.")
            
        return redirect('settings')
        
    return render(request, 'settings.html')

@login_required(login_url='login')
def profile_view(request):
    activity = [
        {'action': 'Account logged in from Chrome on Windows', 'time': '2 minutes ago', 'icon': 'log-in'},
        {'action': 'Synced entire Gmail mailbox', 'time': '10 minutes ago', 'icon': 'refresh-cw'},
        {'action': 'Password successfully validated', 'time': '1 hour ago', 'icon': 'key'},
        {'action': 'Weekly security report generated', 'time': 'Yesterday', 'icon': 'file-text'},
    ]
    return render(request, 'profile.html', {'activity': activity})

def index(request):
    if request.user.is_authenticated:
        return redirect('dashboard')
    return render(request, 'index.html')

@rate_limit_view(key='ip', rate='3/m')
def register_view(request):
    if request.user.is_authenticated:
        return redirect('dashboard')
    return render(request, 'login.html')

@rate_limit_view(key='ip', rate='5/m')
def login_view(request):
    if request.user.is_authenticated:
        return redirect('inbox')
    return render(request, 'login.html')

def logout_view(request):
    logout(request)
    messages.info(request, "You have been logged out.")
    return redirect('index')

import csv
from django.http import HttpResponse, JsonResponse

@login_required(login_url='login')
def mark_notifications_read(request):
    return JsonResponse({'status': 'success'})

@login_required(login_url='login')
def clear_notifications(request):
    return JsonResponse({'status': 'success'})

def about(request):
    from .models import EmailMessage, EmailReport
    
    total_emails = EmailMessage.objects.count()
    threats_detected = EmailMessage.objects.filter(risk__in=['suspicious', 'dangerous']).count()
    
    # Format with commas
    emails_analyzed_str = f"{total_emails:,}" if total_emails > 0 else "0"
    threats_detected_str = f"{threats_detected:,}" if threats_detected > 0 else "0"
    
    context = {
        'emails_analyzed': emails_analyzed_str,
        'threats_detected': threats_detected_str,
        'detection_accuracy': '97',
    }
    return render(request, 'public_about.html', context)

@rate_limit_view(key='ip', rate='2/m')
def contact(request):
    if request.method == 'POST':
        import json
        from django.core.mail import send_mail
        from django.http import JsonResponse
        try:
            data = json.loads(request.body)
            name = data.get('name', '')
            email = data.get('email', '')
            subject = data.get('subject', '')
            message = data.get('message', '')
            
            full_message = f"Name: {name}\nEmail: {email}\n\nMessage:\n{message}"
            
            if name and email and subject and message:
                try:
                    send_mail(
                        subject=f"Contact Form: {subject}",
                        message=full_message,
                        from_email=email,
                        recipient_list=['team.asteroids.2024@gmail.com'],
                        fail_silently=False,
                    )
                    return JsonResponse({'status': 'success', 'message': 'Message sent successfully. We will get back to you shortly.'})
                except Exception as e:
                    return JsonResponse({'status': 'error', 'message': str(e)})
            else:
                return JsonResponse({'status': 'error', 'message': 'All fields are required.'})
        except Exception as e:
            return JsonResponse({'status': 'error', 'message': 'Invalid data.'})
            
    return render(request, 'public_contact.html')

def privacy(request):
    return render(request, 'public_privacy.html')

def terms(request):
    return render(request, 'public_terms.html')

def cookie(request):
    return render(request, 'public_cookie.html')

def support(request):
    return render(request, 'public_support.html')

from django.http import JsonResponse
from django.views.decorators.http import require_POST
import time
import logging
from .services.gemini_service import GeminiService

@login_required(login_url='login')
@require_POST
def generate_explanation(request, id):
    logger = logging.getLogger(__name__)
    email_service = EmailService()
    email = get_object_or_404(EmailMessage, id=id, user=request.user)
    
    if not hasattr(email, 'analysis') or not email.analysis:
        return JsonResponse({'error': 'No threat analysis found.'}, status=404)
        
    report = email.analysis.detailed_report
    analysis_payload = report.get('analysis', report)
    
    # 2. Check if gemini_explanation exists
    if 'gemini_explanation' in analysis_payload and analysis_payload['gemini_explanation']:
        logger.info(f"Cache hit for Gemini explanation on email {id}")
        return JsonResponse({'status': 'cached', 'explanation': analysis_payload['gemini_explanation']})
        
    # 4. Otherwise: Generate explanation
    logger.info(f"Cache miss. Generation started for Gemini explanation on email {id}")
    start_time = time.time()
    
    # Construct input data
    ml_results = email_service.get_email_verdict(email)
    
    # 5. Get Attachment Security Analysis Data
    attachment_findings = []
    if email.has_attachments:
        for att in email.attachments.all():
            if hasattr(att, 'analysis') and att.scan_status == 'COMPLETED':
                attachment_findings.append({
                    'filename': att.filename,
                    'risk_level': att.analysis.risk_level,
                    'risk_score': att.analysis.risk_score,
                    'analyzer_used': att.analysis.analyzer_used,
                    'findings': att.analysis.findings
                })
    
    # Send only structured analysis, no raw data.
    gemini_input_data = {
        'header_analysis': {
            'spf_pass': getattr(email, 'spf_pass', True),
            'dkim_pass': getattr(email, 'dkim_pass', True),
            'dmarc_pass': getattr(email, 'dmarc_pass', True)
        },
        'sender': email.sender_email,
        'sender_reputation': ml_results.get('sender_reputation', 0),
        'url_analysis': report.get('links', []),
        'machine_learning': {
            'prediction': ml_results.get('label', 'UNKNOWN'),
            'confidence': ml_results.get('confidence', 0),
            'features': ml_results.get('features', {})
        },
        'attachment_findings': attachment_findings,
        'overall_risk_score': ml_results.get('score', 0)
    }
    
    gemini_service = GeminiService()
    try:
        gemini_explanation = gemini_service.explain_analysis(gemini_input_data)
        latency_ms = (time.time() - start_time) * 1000
        logger.info(f"Generation completed for email {id}. Latency: {latency_ms:.2f}ms")
        
        # Save into database
        analysis_payload['gemini_explanation'] = gemini_explanation
        if 'analysis' in report:
            report['analysis'] = analysis_payload
        else:
            report.update(analysis_payload)
            
        email.analysis.detailed_report = report
        email.analysis.save(update_fields=['detailed_report'])
        
        return JsonResponse({'status': 'generated', 'explanation': gemini_explanation})
        
    except Exception as e:
        logger.error(f"Error generating Gemini explanation for email {id}: {str(e)}", exc_info=True)
        return JsonResponse({'error': 'Unable to generate AI explanation.'}, status=500)


from .models import Attachment, AttachmentAnalysis
import mimetypes
from django.shortcuts import get_object_or_404

@login_required(login_url='login')
def download_attachment(request, id):
    att = get_object_or_404(Attachment, id=id, email__user=request.user)
    try:
        return FileResponse(att.file.open('rb'), as_attachment=True, filename=att.filename)
    except Exception as e:
        messages.error(request, f"Could not download attachment: {str(e)}")
        return redirect('email_view', id=att.email.id)

@login_required(login_url='login')
def preview_attachment(request, id):
    att = get_object_or_404(Attachment, id=id, email__user=request.user)
    
    if any(ext in att.filename.lower() for ext in ['.exe', '.dll', '.zip', '.tar', '.gz', '.rar', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.bin']):
        messages.warning(request, "Preview is not supported for this file type.")
        return redirect('email_view', id=att.email.id)
        
    try:
        content_type = mimetypes.guess_type(att.filename)[0] or att.content_type or 'application/octet-stream'
        
        # Render Markdown and text formats directly in an HTML wrapper
        ext = att.filename.split('.')[-1].lower()
        if ext in ['md', 'txt', 'json', 'csv', 'yaml', 'yml', 'js', 'py', 'sh']:
            from django.http import HttpResponse
            content = att.file.read().decode('utf-8', errors='replace')
            html = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.8.0/styles/github.min.css">
                <script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.8.0/highlight.min.js"></script>
                <script src="https://cdn.jsdelivr.net/npm/marked/marked.min.js"></script>
                <style>
                    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; padding: 20px; }}
                    #content {{ max-width: 100%; word-wrap: break-word; }}
                </style>
            </head>
            <body>
                <div id="content"></div>
                <script>
                    const ext = "{ext}";
                    const content = {repr(content)};
                    const el = document.getElementById('content');
                    if (ext === 'md') {{
                        el.innerHTML = marked.parse(content);
                    }} else {{
                        const pre = document.createElement('pre');
                        const code = document.createElement('code');
                        code.className = "language-" + ext;
                        code.textContent = content;
                        pre.appendChild(code);
                        el.appendChild(pre);
                        hljs.highlightElement(code);
                    }}
                </script>
            </body>
            </html>
            """
            return HttpResponse(html)
            
        return FileResponse(att.file.open('rb'), content_type=content_type)
    except Exception as e:
        messages.error(request, "Could not load preview.")
        return redirect('email_view', id=att.email.id)

@login_required(login_url='login')
def attachment_analysis_view(request, id):
    att = get_object_or_404(Attachment, id=id, email__user=request.user)
    try:
        analysis = att.analysis
    except AttachmentAnalysis.DoesNotExist:
        messages.warning(request, "Analysis not yet completed or not found.")
        return redirect('email_view', id=att.email.id)
        
    return render(request, 'attachment-analysis.html', {'attachment': att, 'analysis': analysis})
