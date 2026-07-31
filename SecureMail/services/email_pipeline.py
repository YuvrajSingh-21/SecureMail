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
from .gemini_service import GeminiService
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
            self.gemini_service = GeminiService()
            self.ml_predictor = PhishingPredictor()
            self.cat_classifier = CategoryClassifier()
            self.reputation_engine = SenderReputationEngine()
            self.url_validator = URLValidator()
            logger.info("EmailPipeline initialized successfully.")
        except Exception as e:
            logger.error(f"Failed to initialize EmailPipeline: {str(e)}")
            raise

    def run(self, email_id, force=False):
        """
        Runs the full analysis pipeline on a specific email.
        """
        start_time = time.time()
        try:
            email = EmailMessage.objects.select_related('user__profile', 'analysis').get(id=email_id)
            
            # Detect stale analysis (missing centralized analysis payload)
            is_stale = False
            if hasattr(email, 'analysis'):
                if 'analysis' not in email.analysis.detailed_report:
                    is_stale = True
            
            if email.analysis_completed and not force and not is_stale:
                logger.debug(f"Email {email.id} already analyzed. Skipping.")
                return True
                
            if is_stale:
                logger.info(f"Re-analyzing stale intelligence for email {email.id}...")
            else:
                logger.info(f"Starting security pipeline for email ID: {email.id}")
            
            # We use a single transaction for the whole analysis to ensure consistency
            with transaction.atomic():
                # 1. Local ML Prediction (Phishing)
                logger.debug(f"Running ML Phishing prediction for email {email.id}...")
                ml_results = self.ml_predictor.predict_email(
                    email.subject, 
                    email.plain_body or email.snippet or "", 
                    email.sender_email,
                    html_body=email.html_body
                )
                email.ml_score = ml_results['score']
                email.ml_label = ml_results['label']
                email.analysis_reasons = ml_results['reasons']
                
                # Inject Auth Headers for Risk Engine
                if 'features' in ml_results:
                    ml_results['features']['spf_pass'] = getattr(email, 'spf_pass', True)
                    ml_results['features']['dkim_pass'] = getattr(email, 'dkim_pass', True)
                    ml_results['features']['dmarc_pass'] = getattr(email, 'dmarc_pass', True)
                
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
        import urllib.parse
        import re
        
        soup = BeautifulSoup(email.body, 'html.parser')
        urls = []
        for a in soup.find_all('a', href=True):
            url = a['href'].strip()
            if self._is_valid_url(url):
                urls.append(url)
        
        urls = list(set(urls))
        if not urls: return []
        
        # Threat flags
        shorteners = {'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly'}
        suspicious_tlds = {'.zip', '.mov', '.tk', '.ml', '.ga', '.cf', '.gq', '.icu', '.top', '.xyz'}
        
        # GSB Check
        matches = []
        if self.gsb:
            matches = self.gsb.check_urls(urls)
        match_map = {m['threat']['url']: m for m in matches} if matches else {}
        
        results = []
        for url in urls:
            try:
                parsed = urllib.parse.urlparse(url)
                netloc = parsed.netloc.lower()
            except:
                continue
                
            is_malicious = False
            threat_type = 'SAFE'
            risk_score = 0
            gsb_report = match_map.get(url)
            
            # GSB Detection
            if gsb_report:
                is_malicious = True
                threat_type = gsb_report.get('threatType', 'MALWARE')
                risk_score = 90
            
            # Additional Deterministic Detections
            # Punycode
            if 'xn--' in netloc:
                is_malicious = True
                threat_type = 'PUNYCODE_SPOOF'
                risk_score = max(risk_score, 85)
                
            # IP URL
            if re.match(r'^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}$', netloc):
                is_malicious = True
                threat_type = 'IP_URL'
                risk_score = max(risk_score, 80)
                
            # Typosquatting / Fake Microsoft/Google
            target_brands = ['microsoft', 'google', 'paypal', 'apple', 'amazon', 'chase', 'netflix']
            for brand in target_brands:
                if brand in netloc and netloc != f"{brand}.com" and not netloc.endswith(f".{brand}.com"):
                    is_malicious = True
                    threat_type = 'TYPOSQUATTING'
                    risk_score = max(risk_score, 75)
                    
            # URL Shorteners
            if any(s in netloc for s in shorteners):
                risk_score = max(risk_score, 40)
                if threat_type == 'SAFE': threat_type = 'SHORTENER'
                
            # Suspicious TLDs
            if any(netloc.endswith(tld) for tld in suspicious_tlds):
                risk_score = max(risk_score, 50)
                if threat_type == 'SAFE': threat_type = 'SUSPICIOUS_TLD'
                
            # Multiple Redirects (Encoded URLs)
            if url.count('http') > 1 or '%68%74%74%70' in url.lower():
                is_malicious = True
                threat_type = 'MULTIPLE_REDIRECTS'
                risk_score = max(risk_score, 80)
            
            analysis = LinkAnalysis.objects.create(
                email=email,
                url=url,
                is_malicious=is_malicious,
                threat_type=threat_type,
                risk_score=risk_score,
                gsb_report=gsb_report
            )
            results.append({
                'url': url,
                'is_malicious': analysis.is_malicious,
                'risk_score': analysis.risk_score
            })
            if analysis.is_malicious:
                ThreatIndicator.objects.create(
                    email=email,
                    description=f"High risk link detected ({threat_type}): {url[:50]}...",
                    severity='high' if risk_score >= 70 else 'medium'
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
        if not email.has_attachments:
            return results
            
        attachments = Attachment.objects.filter(email=email)
        for attachment in attachments:
            try:
                # Prioritize ATAE (Attachment Analysis Engine) results
                if hasattr(attachment, 'analysis') and attachment.scan_status == 'COMPLETED':
                    is_malicious = attachment.is_malicious
                    risk_score = attachment.analysis.risk_score
                    results.append({'filename': attachment.filename, 'is_malicious': is_malicious, 'risk_score': risk_score})
                    
                    if is_malicious:
                        ThreatIndicator.objects.create(
                            email=email,
                            description=f"Malicious attachment detected (ATAE): {attachment.filename}",
                            severity='critical'
                        )
                    continue

                # Fallback to VirusTotal if ATAE isn't available or hasn't finished
                if self.vt:
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
                        attachment.save(update_fields=['vt_report', 'is_malicious', 'sha256'])
                        results.append({'filename': attachment.filename, 'is_malicious': attachment.is_malicious, 'risk_score': 90 if attachment.is_malicious else 0})
                        
                        if attachment.is_malicious:
                            ThreatIndicator.objects.create(
                                email=email,
                                description=f"Malicious attachment detected (VT): {attachment.filename}",
                                severity='critical'
                            )
            except Exception as e:
                logger.error(f"Failed to analyze attachment {attachment.id}: {str(e)}")
        return results

    def _persist_results(self, email, risk_data, link_results, ml_results):
        email.risk_score = risk_data['score']
        if risk_data['category'] == 'phishing':
            email.risk = 'dangerous'
        elif risk_data['category'] == 'suspicious':
            email.risk = 'suspicious'
        else:
            email.risk = 'safe'
        
        # Finalize verdict using normalized payload
        email.risk_score = risk_data['score']
        email.risk = 'dangerous' if risk_data['label'] == 'PHISHING' else ('suspicious' if risk_data['label'] == 'SUSPICIOUS' else 'safe')
        
        email.ml_score = risk_data['score']
        email.ml_label = risk_data['label']
        email.analysis_reasons = risk_data['reasons']
        email.category = risk_data['label']
        email.sender_reputation = risk_data['sender_reputation']
        email.category_confidence = risk_data['confidence']
        email.analysis_completed = timezone.now()
        email.save()

        # Update Centralized ThreatAnalysis object
        ThreatAnalysis.objects.update_or_create(
            email=email,
            defaults={
                'summary': risk_data['summary'],
                'detailed_report': {
                    'analysis': risk_data,
                    'ml_metadata': ml_results,
                    'links': link_results
                }
            }
        )

    def _update_user_profile(self, email):
        from .profile_service import ProfileService as MetricProfileService
        from SecureMail.models import Notification
        
        MetricProfileService.recalculate_security_metrics(email.user)
        
        try:
            profile = email.user.profile
            if email.risk == 'dangerous' and profile.alert_threats:
                Notification.objects.create(
                    user=email.user,
                    title="Phishing Threat Detected",
                    message=f"A dangerous email '{email.subject}' was detected.",
                    type='threat'
                )
        except Exception as e:
            logger.error(f"Failed to create notification: {str(e)}")
