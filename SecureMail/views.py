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
    manager = SyncManager(request.user)
    job = manager.start_sync(full_sync=full_sync)
    
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
    emails = EmailMessage.objects.filter(user=request.user)
    
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
def email_view(request, id):
    email_service = EmailService()
    email = email_service.get_email_detail(request.user, id)
    
    # Calculate offset for Email View SVG (r=70, circumference approx 439.8)
    # Aligning with user requirement: "Threat Index must equal ml_score"
    score = email.ml_score if email.ml_score is not None else 0
    email.score_offset = 439.8 * (1 - score / 100)
    
    return render(request, 'email-view.html', {'email': email})

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
        service = ProfileService()
        service.update_protection(request.user, is_protected)
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
