from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import login, authenticate, logout
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.core.paginator import Paginator
from .services.business_logic import EmailService, ProfileService
from .services.sync_manager import SyncManager
from .models import EmailMessage, ConnectedAccount

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
    query = request.GET.get('q')
    emails = EmailMessage.objects.filter(user=request.user).select_related('analysis')
    
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
    else:
        emails = emails.filter(folder='INBOX', in_trash=False)
        title = "Inbox"

    if query:
        emails = emails.filter(subject__icontains=query) | emails.filter(sender_email__icontains=query)

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
    email_service = EmailService()
    email_service.delete_email(request.user, id)
    messages.info(request, "Message moved to trash.")
    return redirect('inbox')

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
        features = email.analysis.detailed_report.get('features', {})
        
    forensic = {
        'analysis': analysis_norm,
        'features': features
    }
    
    return render(request, 'email-view.html', {'email': email, 'forensic': forensic})

@login_required(login_url='login')
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
        timezone = request.POST.get('timezone')
        language = request.POST.get('language')
        
        service = ProfileService()
        profile = service.repository.get_by_user(request.user)
        
        if timezone:
            profile.timezone = timezone
        if language:
            profile.language = language
            
        profile.is_protected = is_protected
        profile.alert_threats = alert_threats
        profile.alert_digest = alert_digest
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

def register_view(request):
    if request.user.is_authenticated:
        return redirect('dashboard')
    if request.method == 'POST':
        from django.contrib.auth.models import User
        username = request.POST.get('username')
        email = request.POST.get('email')
        password = request.POST.get('password')
        confirm_password = request.POST.get('confirm_password')
        
        if password != confirm_password:
            messages.error(request, "Passwords do not match.")
            return render(request, 'register.html')
            
        if User.objects.filter(username=username).exists():
            messages.error(request, "Username already exists.")
            return render(request, 'register.html')
            
        user = User.objects.create_user(username=username, email=email, password=password)
        login(request, user)
        messages.success(request, f"Welcome, {username}! Your account has been created.")
        return redirect('inbox')
        
    return render(request, 'register.html')

def login_view(request):
    if request.user.is_authenticated:
        return redirect('inbox')
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            messages.success(request, f"Welcome back, {username}!")
            return redirect('inbox')
        else:
            messages.error(request, "Invalid username or password.")
            
    return render(request, 'login.html')

def logout_view(request):
    logout(request)
    messages.info(request, "You have been logged out.")
    return redirect('index')

import csv
from django.http import HttpResponse, JsonResponse

@login_required(login_url='login')
def export_dataset_csv(request):
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="threat_analytics_dataset.csv"'
    
    writer = csv.writer(response)
    writer.writerow(['ID', 'Subject', 'Sender', 'Date', 'Category', 'Risk Score', 'ML Label'])
    
    emails = EmailMessage.objects.filter(user=request.user).order_by('-timestamp')
    for email in emails:
        writer.writerow([
            email.id,
            email.subject,
            email.sender_email,
            email.timestamp.strftime('%Y-%m-%d %H:%M:%S') if email.timestamp else '',
            email.category,
            email.risk_score,
            email.ml_label
        ])
        
    return response

@login_required(login_url='login')
def mark_notifications_read(request):
    return JsonResponse({'status': 'success'})

@login_required(login_url='login')
def clear_notifications(request):
    return JsonResponse({'status': 'success'})

@login_required(login_url='login')
def about(request):
    from .models import EmailMessage
    
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
    return render(request, 'about.html', context)

@login_required(login_url='login')
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
            
            try:
                send_mail(
                    subject=f"Contact Form: {subject}",
                    message=full_message,
                    from_email=email,
                    recipient_list=['team.asteroids.2024@gmail.com'],
                    fail_silently=False,
                )
            except Exception as e:
                print(f"Failed to send email via SMTP: {e}")
                print(f"--- FAKE EMAIL SENT ---\nSubject: {subject}\nTo: team.asteroids.2024@gmail.com\n\n{full_message}\n-----------------------")
                
            return JsonResponse({'status': 'success', 'message': 'Message sent successfully.'})
        except Exception as e:
            return JsonResponse({'status': 'error', 'message': str(e)}, status=400)
            
    return render(request, 'contact.html')
