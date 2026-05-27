from django.contrib import admin
from .models import Profile, EmailMessage, Attachment, ThreatIndicator, ThreatAnalysis, Notification, LinkAnalysis, RiskScore

@admin.register(Profile)
class ProfileAdmin(admin.ModelAdmin):
    list_display = ('user', 'security_score', 'emails_scanned', 'threats_blocked', 'is_protected')
    search_fields = ('user__username', 'connected_gmail')

class AttachmentInline(admin.TabularInline):
    model = Attachment
    extra = 0

class ThreatIndicatorInline(admin.TabularInline):
    model = ThreatIndicator
    extra = 0

class LinkAnalysisInline(admin.TabularInline):
    model = LinkAnalysis
    extra = 0

class RiskScoreInline(admin.StackedInline):
    model = RiskScore
    can_delete = False

@admin.register(EmailMessage)
class EmailMessageAdmin(admin.ModelAdmin):
    list_display = ('subject', 'sender_email', 'user', 'risk', 'risk_score', 'timestamp', 'unread')
    list_filter = ('risk', 'unread', 'starred', 'in_trash')
    search_fields = ('subject', 'sender_email', 'body')
    inlines = [AttachmentInline, ThreatIndicatorInline, LinkAnalysisInline, RiskScoreInline]
    actions = ['analyze_security']

    def analyze_security(self, request, queryset):
        from .services.email_pipeline import EmailPipeline
        pipeline = EmailPipeline()
        count = 0
        for email in queryset:
            if pipeline.run(email.id):
                count += 1
        self.message_user(request, f"Successfully analyzed {count} emails.")
    analyze_security.short_description = "Run Security Analysis Pipeline"

@admin.register(LinkAnalysis)
class LinkAnalysisAdmin(admin.ModelAdmin):
    list_display = ('url', 'email', 'threat_type', 'risk_score', 'is_malicious')
    list_filter = ('threat_type', 'is_malicious')
    search_fields = ('url',)

@admin.register(ThreatAnalysis)
class ThreatAnalysisAdmin(admin.ModelAdmin):
    list_display = ('email', 'generated_at')

@admin.register(Notification)
class NotificationAdmin(admin.ModelAdmin):
    list_display = ('title', 'user', 'type', 'read', 'created_at')
    list_filter = ('type', 'read')
