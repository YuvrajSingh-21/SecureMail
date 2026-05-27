from django.core.management.base import BaseCommand
from django.contrib.auth.models import User
from SecureMail.models import EmailMessage, ThreatIndicator, ThreatAnalysis
import random
from django.utils import timezone

class Command(BaseCommand):
    help = 'Seeds the database with mock email data'

    def handle(self, *args, **options):
        # Create a default user if none exists
        if not User.objects.exists():
            user = User.objects.create_user(username='demo', email='demo@example.com', password='password123')
            self.stdout.write(self.style.SUCCESS('Created demo user: demo / password123'))
        else:
            user = User.objects.first()

        # Clear existing emails for this user to avoid duplicates on multiple runs
        EmailMessage.objects.filter(user=user).delete()

        mock_data = [
            {
                'sender_name': 'Amazon Security',
                'sender_email': 'security@amaz0n-verify.com',
                'subject': 'Urgent: Verify Your Account Now!',
                'body': 'Dear Customer,\n\nWe have detected unusual activity on your Amazon account. Your account will be suspended within 24 hours unless you verify your identity immediately.\n\nClick the link below to verify:\nhttps://amaz0n-verify.com/secure-login\n\nPlease provide your full name, credit card number, and social security number for verification.\n\nAmazon Security Team',
                'risk': 'dangerous',
                'risk_score': 92,
                'threats': [
                    'Fake sender domain (amaz0n-verify.com)',
                    'Urgency tactics',
                    'Requests sensitive information',
                    'Suspicious URL detected',
                    'Domain mismatch with official Amazon'
                ]
            },
            {
                'sender_name': 'John Smith',
                'sender_email': 'john.smith@company.com',
                'subject': 'Q4 Budget Review Meeting',
                'body': 'Hi team,\n\nPlease find attached the Q4 budget review presentation for our meeting tomorrow at 2 PM.\n\nKey discussion points:\n- Revenue projections\n- Cost optimization\n- Hiring plans\n\nLet me know if you have any questions.\n\nBest,\nJohn',
                'risk': 'safe',
                'risk_score': 8,
                'threats': []
            },
            {
                'sender_name': 'Netflix Billing',
                'sender_email': 'billing@netflix-renew.net',
                'subject': 'Payment Failed - Update Now',
                'body': 'Hello,\n\nWe were unable to process your monthly payment for your Netflix subscription. Please update your payment information within 48 hours to avoid service interruption.\n\nUpdate Payment: https://netflix-renew.net/billing\n\nNetflix Billing Team',
                'risk': 'suspicious',
                'risk_score': 67,
                'threats': [
                    'Unofficial domain (netflix-renew.net)',
                    'Payment urgency tactic',
                    'Suspicious link detected'
                ]
            },
            {
                'sender_name': 'FedEx Express',
                'sender_email': 'delivery@fedx-tracking.info',
                'subject': 'Package Delivery Notification #82734',
                'body': 'Your package is currently held at our distribution center due to an incomplete delivery address. Please pay the redelivery fee of $2.99 to schedule a new delivery time.\n\nPay here: http://fedx-tracking.info/pay\n\nFailure to pay will result in the package being returned to the sender.',
                'risk': 'dangerous',
                'risk_score': 85,
                'threats': [
                    'Typosquatting domain (fedx instead of fedex)',
                    'Small payment request (common scam tactic)',
                    'Link to non-secure HTTP site'
                ]
            },
            {
                'sender_name': 'Microsoft Office 365',
                'sender_email': 'no-reply@sharepoint-docs.com',
                'subject': 'New document shared with you: "Payroll_Q1_2026.pdf"',
                'body': 'A new document has been shared with you via SharePoint. You can view the document by clicking the button below.\n\n[View Document]\n\nLink: https://sharepoint-docs.com/auth/login?redirect=payroll\n\nThis is an automated notification.',
                'risk': 'dangerous',
                'risk_score': 89,
                'threats': [
                    'Deceptive document naming (Payroll)',
                    'Fake login page detected at link',
                    'Suspicious document sharing platform'
                ]
            },
            {
                'sender_name': 'System Draft',
                'sender_email': 'me@securemail.ai',
                'subject': '[Draft] Project Proposal Revisions',
                'body': 'Draft content for the upcoming project proposal...',
                'risk': 'safe',
                'risk_score': 0,
                'threats': []
            },
            {
                'sender_name': 'HR Department',
                'sender_email': 'hr@internal-company.com',
                'subject': 'Mandatory Security Training',
                'body': 'Please complete your annual security awareness training by Friday.',
                'risk': 'suspicious',
                'risk_score': 45,
                'threats': ['Urgency tactic']
            }
        ]

        for data in mock_data:
            threats = data.pop('threats')
            email = EmailMessage.objects.create(
                user=user,
                recipient_email=user.email,
                **data
            )
            
            for threat_desc in threats:
                ThreatIndicator.objects.create(
                    email=email,
                    description=threat_desc,
                    severity='high' if data['risk'] == 'dangerous' else 'medium'
                )
                
            if data['risk'] != 'safe':
                ThreatAnalysis.objects.create(
                    email=email,
                    summary=f"Analysis of '{data['subject']}' detected multiple indicators of {data['risk']} activity.",
                    detailed_report={'score': data['risk_score'], 'findings': threats}
                )

        self.stdout.write(self.style.SUCCESS(f'Successfully seeded {len(mock_data)} emails for user {user.username}'))
