from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone

class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile', db_index=True)
    avatar = models.ImageField(upload_to='avatars/', null=True, blank=True)
    security_score = models.FloatField(default=100.0)
    emails_scanned = models.IntegerField(default=0)
    threats_blocked = models.IntegerField(default=0)
    connected_gmail = models.EmailField(null=True, blank=True)
    is_protected = models.BooleanField(default=True)
    alert_threats = models.BooleanField(default=True)
    alert_digest = models.BooleanField(default=True)
    timezone = models.CharField(max_length=50, default='UTC (Coordinated Universal Time)')
    language = models.CharField(max_length=50, default='English (US)')

    class Meta:
        indexes = [
            models.Index(fields=['user']),
        ]

    def __str__(self):
        return f"{self.user.username}'s Profile"

class EmailMessageManager(models.Manager):
    def active(self, user):
        """Single source of truth: excludes remote deleted emails."""
        return self.filter(user=user, is_remote_deleted=False)

    def inbox(self, user):
        return self.active(user).filter(in_trash=False).order_by('-timestamp')
    
    def starred(self, user):
        return self.active(user).filter(starred=True, in_trash=False).order_by('-timestamp')
    
    def trash(self, user):
        return self.active(user).filter(in_trash=True).order_by('-timestamp')

class EmailMessage(models.Model):
    RISK_LEVELS = (
        ('safe', 'Safe'),
        ('suspicious', 'Suspicious'),
        ('dangerous', 'Dangerous'),
    )
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='emails', db_index=True)
    gmail_message_id = models.CharField(max_length=255, null=True, blank=True, db_index=True)
    thread_id = models.CharField(max_length=255, null=True, blank=True, db_index=True)
    
    sender_email = models.EmailField(db_index=True)
    sender_name = models.CharField(max_length=255, null=True, blank=True)
    recipient_email = models.EmailField(db_index=True)
    subject = models.CharField(max_length=255)
    body = models.TextField() # Legacy field
    
    plain_body = models.TextField(null=True, blank=True)
    html_body = models.TextField(null=True, blank=True)
    
    snippet = models.TextField(null=True, blank=True)
    
    timestamp = models.DateTimeField(default=timezone.now, db_index=True)
    unread = models.BooleanField(default=True, db_index=True)
    starred = models.BooleanField(default=False, db_index=True)
    in_trash = models.BooleanField(default=False, db_index=True)
    is_remote_deleted = models.BooleanField(default=False, db_index=True)
    
    folder = models.CharField(max_length=50, default='INBOX', db_index=True)
    
    risk_score = models.FloatField(default=0.0, db_index=True)
    risk = models.CharField(max_length=20, choices=RISK_LEVELS, default='safe', db_index=True)
    
    has_attachments = models.BooleanField(default=False)
    
    # Auth Headers
    spf_pass = models.BooleanField(default=True)
    dkim_pass = models.BooleanField(default=True)
    dmarc_pass = models.BooleanField(default=True)
    
    # ML Analysis Results
    ml_score = models.FloatField(default=0.0, db_index=True)
    ml_label = models.CharField(max_length=20, default='SAFE', db_index=True)
    analysis_version = models.CharField(max_length=50, default='1.0.0')
    
    # Intelligence Engine Phase 2
    category = models.CharField(max_length=50, default='UNKNOWN', db_index=True)
    category_confidence = models.FloatField(default=0.0)
    sender_reputation = models.FloatField(default=50.0)
    analysis_reasons = models.JSONField(default=list)
    analysis_completed = models.DateTimeField(null=True, blank=True)

    objects = EmailMessageManager()

    class Meta:
        indexes = [
            models.Index(fields=['user', 'timestamp']),
            models.Index(fields=['user', 'in_trash', 'timestamp']),
            models.Index(fields=['risk']),
            models.Index(fields=['gmail_message_id']),
            models.Index(fields=['sender_email']),
            models.Index(fields=['timestamp']),
            models.Index(fields=['ml_score']),
            models.Index(fields=['ml_label']),
            models.Index(fields=['category']),
        ]
        unique_together = ('user', 'gmail_message_id')

    def __str__(self):
        return f"{self.subject} from {self.sender_email}"
        
    @property
    def verdict(self):
        from .services.risk_engine import RiskEngine
        engine = RiskEngine()
        
        report = {}
        # hasattr can trigger an N+1 if analysis isn't prefetched,
        # but views using this should use .select_related('analysis')
        if hasattr(self, 'analysis'):
            report = self.analysis.detailed_report
            
        return engine.normalize_payload(report)

class SenderReputationModel(models.Model):
    domain = models.CharField(max_length=255, unique=True, db_index=True)
    frequency = models.IntegerField(default=0)
    historical_safe_count = models.IntegerField(default=0)
    historical_phishing_count = models.IntegerField(default=0)
    reputation_score = models.FloatField(default=50.0)

    def __str__(self):
        return f"{self.domain} - Score: {self.reputation_score}"

class SyncJob(models.Model):
    STATUS_CHOICES = (
        ('PENDING', 'Pending'),
        ('RUNNING', 'Running'),
        ('COMPLETED', 'Completed'),
        ('FAILED', 'Failed'),
    )

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='sync_jobs')
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='PENDING')
    total_messages = models.IntegerField(default=0)
    synced_messages = models.IntegerField(default=0)
    last_page_token = models.TextField(null=True, blank=True)
    error_message = models.TextField(null=True, blank=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Sync for {self.user.username} - {self.status}"

class Attachment(models.Model):
    email = models.ForeignKey(EmailMessage, on_delete=models.CASCADE, related_name='attachments', db_index=True)
    file = models.FileField(upload_to='attachments/')
    filename = models.CharField(max_length=255)
    size = models.IntegerField() # In bytes
    content_type = models.CharField(max_length=100)
    sha256 = models.CharField(max_length=64, null=True, blank=True, db_index=True)
    is_malicious = models.BooleanField(default=False)
    vt_report = models.JSONField(null=True, blank=True)

    def __str__(self):
        return self.filename

class LinkAnalysis(models.Model):
    email = models.ForeignKey(EmailMessage, on_delete=models.CASCADE, related_name='link_analyses', db_index=True)
    url = models.URLField(max_length=2000)
    threat_type = models.CharField(max_length=100, null=True, blank=True)
    confidence = models.FloatField(default=0.0)
    risk_score = models.FloatField(default=0.0)
    is_malicious = models.BooleanField(default=False)
    gsb_report = models.JSONField(null=True, blank=True)

    class Meta:
        verbose_name_plural = "Link Analyses"

    def __str__(self):
        return self.url[:50]

class RiskScore(models.Model):
    CATEGORIES = (
        ('safe', 'Safe'),
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('critical', 'Critical'),
    )

    email = models.OneToOneField(EmailMessage, on_delete=models.CASCADE, related_name='detailed_risk', db_index=True)
    score = models.FloatField(default=0.0) # 0-100
    category = models.CharField(max_length=20, choices=CATEGORIES, default='safe')
    
    # Factors
    content_risk = models.FloatField(default=0.0)
    link_risk = models.FloatField(default=0.0)
    attachment_risk = models.FloatField(default=0.0)
    reputation_risk = models.FloatField(default=0.0)
    
    explanation = models.TextField()
    factors_json = models.JSONField(default=dict)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.score} - {self.category}"

class ThreatIndicator(models.Model):
    email = models.ForeignKey(EmailMessage, on_delete=models.CASCADE, related_name='indicators', db_index=True)
    description = models.CharField(max_length=500)
    severity = models.CharField(max_length=20, default='medium') # low, medium, high

    def __str__(self):
        return f"{self.severity}: {self.description[:30]}..."

class ThreatAnalysis(models.Model):
    email = models.OneToOneField(EmailMessage, on_delete=models.CASCADE, related_name='analysis', db_index=True)
    summary = models.TextField()
    detailed_report = models.JSONField(default=dict)
    generated_at = models.DateTimeField(auto_now_add=True)

class Notification(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='notifications', db_index=True)
    title = models.CharField(max_length=255)
    message = models.TextField()
    type = models.CharField(max_length=50, default='info') # info, warning, threat
    read = models.BooleanField(default=False, db_index=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        indexes = [
            models.Index(fields=['user', 'created_at']),
            models.Index(fields=['user', 'read']),
        ]

class ConnectedAccount(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='google_account')
    provider = models.CharField(max_length=50, default='google')
    email = models.EmailField()
    google_id = models.CharField(max_length=255, unique=True)
    access_token = models.TextField()
    refresh_token = models.TextField(null=True, blank=True)
    token_expiry = models.DateTimeField()
    profile_picture = models.URLField(max_length=500, null=True, blank=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.email} ({self.user.username})"
