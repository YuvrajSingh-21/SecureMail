import logging
import os
import re
import time
from bs4 import BeautifulSoup
from django.db import transaction
from django.core.validators import URLValidator
from django.core.exceptions import ValidationError
from ..models import EmailMessage, Attachment, LinkAnalysis, RiskScore, ThreatAnalysis, ThreatIndicator
from .virustotal_service import VirusTotalService
from .safe_browsing_service import SafeBrowsingService
from .risk_engine import RiskEngine
from ..ml.predictor import PhishingPredictor
from ..ml.category_classifier import CategoryClassifier
from ..ml.sender_reputation import SenderReputationEngine
from django.utils import timezone

logger = logging.getLogger(__name__)

class EmailPipeline:
    """
    A formalized pipeline for analyzing emails through multiple security layers.
    REFACTORED: Enhanced logging and failure resilience.
    """
    def __init__(self):
        try:
            self.vt = VirusTotalService() if os.getenv('VIRUSTOTAL_API_KEY') else None
            self.gsb = SafeBrowsingService() if os.getenv('SAFE_BROWSING_API_KEY') else None
            self.engine = RiskEngine()
            self.ml_predictor = PhishingPredictor()
            self.cat_classifier = CategoryClassifier()
            self.reputation_engine = SenderReputationEngine()
            self.url_validator = URLValidator()
            logger.info("EmailPipeline initialized successfully.")
        except Exception as e:
            logger.error(f"Failed to initialize EmailPipeline: {str(e)}")
            raise

    def run(self, email_id):
        """
        Runs the full analysis pipeline on a specific email.
        """
        start_time = time.time()
        try:
            email = EmailMessage.objects.select_related('user__profile').get(id=email_id)
            
            if email.analysis_completed:
                logger.debug(f"Email {email.id} already analyzed. Skipping.")
                return True
                
            logger.info(f"Starting security pipeline for email ID: {email.id}")
            
            # We use a single transaction for the whole analysis to ensure consistency
            with transaction.atomic():
                # 1. Local ML Prediction (Phishing)
                logger.debug(f"Running ML Phishing prediction for email {email.id}...")
                ml_results = self.ml_predictor.predict_email(
                    email.subject, 
                    email.plain_body or email.snippet or "", 
                    email.sender_email
                )
                email.ml_score = ml_results['score']
                email.ml_label = ml_results['label']
                email.analysis_reasons = ml_results['reasons']
                
                # 2. Local ML Category Classification
                logger.debug(f"Running Category classification for email {email.id}...")
                cat_results = self.cat_classifier.predict_category(email.subject, email.body, email.sender_email, email.sender_name)
                email.category = cat_results['category']
                email.category_confidence = cat_results['confidence']
                
                # 3. Sender Reputation Check
                domain = email.sender_email.split('@')[-1].lower() if '@' in email.sender_email else ''
                rep_score = self.reputation_engine.get_reputation(domain)
                email.sender_reputation = rep_score
                
                # 4. Link Analysis (GSB)
                logger.debug(f"Running Link analysis for email {email.id}...")
                link_results = self._analyze_links(email)
                
                # 5. Malware Analysis (VT)
                logger.debug(f"Running Attachment analysis for email {email.id}...")
                attachment_results = self._analyze_attachments(email)
                
                # 6. Final Risk Calculation
                logger.debug(f"Calculating final risk for email {email.id}...")
                risk_data = self.engine.calculate_risk(
                    gemini_result=ml_results, 
                    link_results=link_results,
                    attachment_results=attachment_results,
                    sender_email=email.sender_email
                )
                
                # 7. Update Reputation (Post-Analysis)
                is_phishing = risk_data['category'] in ['high', 'critical'] or email.ml_label == 'PHISHING'
                self.reputation_engine.update_reputation(domain, is_phishing)
                
                # 8. Save Results
                self._persist_results(email, risk_data, link_results, ml_results)
                
                # 9. Mark as completed
                email.analysis_completed = timezone.now()
                email.save()
                
                # 10. Update User Profile
                self._update_user_profile(email)
                
                latency_ms = (time.time() - start_time) * 1000
                logger.info(f"Analysis SUCCESS - ID: {email.id}, Label: {email.ml_label}, Cat: {email.category}, Score: {email.risk_score}, Latency: {latency_ms:.2f}ms")
                return True

        except EmailMessage.DoesNotExist:
            logger.error(f"Email {email_id} not found in database.")
            return False
        except Exception as e:
            logger.error(f"Pipeline CRASHED for email {email_id}: {str(e)}", exc_info=True)
            return False

    def _analyze_links(self, email):
        if not self.gsb:
            return []
        
        soup = BeautifulSoup(email.body, 'html.parser')
        urls = []
        for a in soup.find_all('a', href=True):
            url = a['href'].strip()
            if self._is_valid_url(url):
                urls.append(url)
        
        urls = list(set(urls))
        if not urls: return []

        matches = self.gsb.check_urls(urls)
        match_map = {m['threat']['url']: m for m in matches}
        
        results = []
        for url in urls:
            match = match_map.get(url)
            analysis = LinkAnalysis.objects.create(
                email=email,
                url=url,
                is_malicious=bool(match),
                threat_type=match.get('threatType') if match else 'SAFE',
                risk_score=90 if match else 0,
                gsb_report=match
            )
            results.append({
                'url': url,
                'is_malicious': analysis.is_malicious,
                'risk_score': analysis.risk_score
            })
            if analysis.is_malicious:
                ThreatIndicator.objects.create(
                    email=email,
                    description=f"Malicious link detected: {url[:50]}...",
                    severity='high'
                )
        return results

    def _is_valid_url(self, url):
        if not url.startswith(('http://', 'https://')): return False
        try:
            self.url_validator(url)
            return True
        except ValidationError:
            return False

    def _analyze_attachments(self, email):
        results = []
        if not self.vt or not email.has_attachments:
            return results
            
        attachments = Attachment.objects.filter(email=email)
        for attachment in attachments:
            try:
                file_hash = self.vt.get_file_hash(attachment.file.path)
                attachment.sha256 = file_hash
                report = self.vt.scan_hash(file_hash)
                
                if not report:
                    scan_info = self.vt.scan_file(attachment.file.path)
                    if scan_info:
                        time.sleep(0.5)
                        report = self.vt.get_report(scan_info.get('data', {}).get('id'))
                
                if report:
                    attachment.vt_report = report
                    attachment.is_malicious = self.vt.is_malicious_report(report)
                    attachment.save()
                    results.append({'filename': attachment.filename, 'is_malicious': attachment.is_malicious})
                    
                    if attachment.is_malicious:
                        ThreatIndicator.objects.create(
                            email=email,
                            description=f"Malware found in {attachment.filename}",
                            severity='high'
                        )
            except Exception as e:
                logger.error(f"Attachment scan failed: {str(e)}")
        return results

    def _persist_results(self, email, risk_data, link_results, ml_results):
        email.risk_score = risk_data['score']
        if risk_data['category'] == 'phishing':
            email.risk = 'dangerous'
        elif risk_data['category'] == 'suspicious':
            email.risk = 'suspicious'
        else:
            email.risk = 'safe'
        email.save()

        RiskScore.objects.update_or_create(
            email=email,
            defaults={
                'score': risk_data['score'],
                'category': risk_data['category'],
                'content_risk': risk_data['factors']['content'],
                'link_risk': risk_data['factors']['links'],
                'attachment_risk': risk_data['factors']['attachments'],
                'reputation_risk': risk_data['factors']['reputation'],
                'explanation': risk_data['explanation'],
                'factors_json': risk_data['factors']
            }
        )

        reasons = ml_results.get('reasons', [])
        summary = risk_data['explanation']
        if reasons:
            summary += "\n\nLocal Engine Observations:\n- " + "\n- ".join(reasons)

        ThreatAnalysis.objects.update_or_create(
            email=email,
            defaults={
                'summary': summary,
                'detailed_report': {
                    'links': link_results,
                    'ml_metadata': ml_results
                }
            }
        )

    def _update_user_profile(self, email):
        from django.db.models import Avg
        profile = email.user.profile
        profile.emails_scanned = EmailMessage.objects.filter(user=email.user, analysis_completed__isnull=False).count()
        profile.threats_blocked = EmailMessage.objects.filter(user=email.user, risk='dangerous').count()
        
        avg_risk = EmailMessage.objects.filter(user=email.user, analysis_completed__isnull=False).order_by('-timestamp')[:50].aggregate(Avg('risk_score'))['risk_score__avg'] or 0
        profile.security_score = max(0, 100 - avg_risk)
        profile.save()
