import pandas as pd
import os
import logging

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format='%(message)s')

class DatasetBuilder:
    def __init__(self):
        self.ml_dir = os.path.dirname(__file__)
        self.datasets_dir = os.path.join(self.ml_dir, 'datasets')
        os.makedirs(self.datasets_dir, exist_ok=True)
        
        # Define paths
        self.path_phish_data = os.path.join(self.ml_dir, 'email_phishing_data.csv')
        self.path_phish_email = os.path.join(self.ml_dir, 'Phishing_Email.csv')
        self.path_ceas_08 = os.path.join(self.ml_dir, 'CEAS_08.csv')
        self.output_path = os.path.join(self.datasets_dir, 'combined_dataset.csv')

    def normalize_label(self, val):
        """
        Normalize labels to SAFE, PHISHING, or SPAM.
        """
        val_str = str(val).strip().lower()
        if val_str in ['safe email', 'ham', '0', '0.0']:
            return 'SAFE'
        if val_str in ['phishing email', '1', '1.0']:
            return 'PHISHING'
        if val_str == 'spam':
            return 'SPAM'
        return 'UNKNOWN'

    def build(self):
        dfs = []

        # 1. Load email_phishing_data.csv
        if os.path.exists(self.path_phish_data):
            logger.info(f"Processing {os.path.basename(self.path_phish_data)}...")
            df1 = pd.read_csv(self.path_phish_data)
            df1_new = pd.DataFrame()
            df1_new['sender'] = ""
            df1_new['subject'] = ""
            df1_new['body'] = ""
            df1_new['label'] = df1['label'].apply(self.normalize_label)
            dfs.append(df1_new)

        # 2. Load Phishing_Email.csv
        if os.path.exists(self.path_phish_email):
            logger.info(f"Processing {os.path.basename(self.path_phish_email)}...")
            df2 = pd.read_csv(self.path_phish_email)
            df2_new = pd.DataFrame()
            df2_new['sender'] = ""
            df2_new['subject'] = ""
            df2_new['body'] = df2['Email Text']
            df2_new['label'] = df2['Email Type'].apply(self.normalize_label)
            dfs.append(df2_new)

        # 3. Load CEAS_08.csv
        if os.path.exists(self.path_ceas_08):
            logger.info(f"Processing {os.path.basename(self.path_ceas_08)}...")
            df3 = pd.read_csv(self.path_ceas_08)
            df3_new = pd.DataFrame()
            df3_new['sender'] = df3['sender']
            df3_new['subject'] = df3['subject']
            df3_new['body'] = df3['body']
            df3_new['label'] = df3['label'].apply(self.normalize_label)
            dfs.append(df3_new)

        if not dfs:
            logger.error("No datasets were loaded.")
            return

        # Combine
        combined_df = pd.concat(dfs, ignore_index=True)
        combined_df = combined_df.dropna(subset=['label'])
        combined_df = combined_df[combined_df['label'] != 'UNKNOWN']
        combined_df = combined_df.drop_duplicates()
        combined_df = combined_df.fillna("")
        
        # Statistics
        safe_count = len(combined_df[combined_df['label'] == 'SAFE'])
        phish_count = len(combined_df[combined_df['label'] == 'PHISHING'])
        spam_count = len(combined_df[combined_df['label'] == 'SPAM'])
        total_rows = len(combined_df)
        
        logger.info("\n--- Dataset Statistics ---")
        logger.info(f"SAFE count:     {safe_count}")
        logger.info(f"PHISHING count: {phish_count}")
        logger.info(f"SPAM count:     {spam_count}")
        logger.info(f"TOTAL rows:     {total_rows}")
        
        # Save
        combined_df.to_csv(self.output_path, index=False)
        logger.info(f"\nUnified dataset saved to: {self.output_path}")

    def build_unified_dataset(self):
        """
        Builds a rich synthetic dataset for categories and phishing detection.
        Used for bootstrapping models.
        """
        data = []
        # Categories mapping
        # 1. Bank / Phishing
        data.append({"subject": "Action Required: Your account has been suspended!", "body": "Verify your identity immediately at http://192.168.1.1/login. Update your password now.", "sender": "security@amaz0n-urgent.net", "label": "PHISHING", "category": "PHISHING"})
        data.append({"subject": "Unusual login attempt", "body": "Someone logged into your account. Click here to secure it: http://bit.ly/2A3Df", "sender": "alert@paypal-update.com", "label": "PHISHING", "category": "PHISHING"})
        # 2. Banking / Safe
        data.append({"subject": "Your monthly statement is ready", "body": "View your statement securely on your Chase app.", "sender": "no-reply@chase.com", "label": "SAFE", "category": "BANKING"})
        # 3. OTP
        data.append({"subject": "Your verification code: 492104", "body": "Use this code to login. Do not share this code.", "sender": "auth@google.com", "label": "SAFE", "category": "OTP"})
        # 4. Newsletter
        data.append({"subject": "Top 10 Security Tips for 2026", "body": "Welcome to our weekly newsletter! Unsubscribe at the bottom.", "sender": "news@techcrunch.com", "label": "SAFE", "category": "NEWSLETTER"})
        # 5. Personal
        data.append({"subject": "Lunch tomorrow?", "body": "Hey, let's grab food at noon. See ya!", "sender": "john.doe@gmail.com", "label": "SAFE", "category": "PERSONAL"})
        # 6. Invoice
        data.append({"subject": "Invoice INV-2026-001", "body": "Please find attached your invoice for services rendered.", "sender": "billing@stripe.com", "label": "SAFE", "category": "INVOICE"})
        # 7. Spam
        data.append({"subject": "Lose 10 pounds in 1 week!!!", "body": "Buy our new magic pills today. 100% guarantee.", "sender": "sales@magicpills.xyz", "label": "SPAM", "category": "SPAM"})

        # Ensure all categories are represented at least once to avoid XGBoost missing class errors
        from .category_classifier import CategoryClassifier
        for cat in CategoryClassifier.CATEGORIES:
            data.append({"subject": f"Sample {cat}", "body": f"This is a {cat} email.", "sender": f"info@{cat.lower()}.com", "label": "SAFE", "category": cat})

        df = pd.DataFrame(data * 50)
        return df

if __name__ == "__main__":
    builder = DatasetBuilder()
    builder.build()
