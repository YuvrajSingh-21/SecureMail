import os
import joblib
import json
import pandas as pd
import numpy as np
import logging
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import classification_report, accuracy_score, precision_recall_fscore_support
import xgboost as xgb

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format='%(message)s')

class PhishingModelTrainer:
    def __init__(self):
        self.ml_dir = os.path.dirname(__file__)
        self.dataset_path = os.path.join(self.ml_dir, 'datasets', 'combined_dataset.csv')
        self.models_dir = os.path.join(self.ml_dir, 'models')
        os.makedirs(self.models_dir, exist_ok=True)
        
        self.label_map = {'SAFE': 0, 'PHISHING': 1, 'SPAM': 2}
        self.reverse_label_map = {v: k for k, v in self.label_map.items()}

    def load_and_preprocess(self):
        logger.info(f"Loading dataset from {self.dataset_path}...")
        df = pd.read_csv(self.dataset_path)
        
        # Combine subject and body
        df['text'] = df['subject'].fillna('') + " " + df['body'].fillna('')
        
        # Filter for valid labels and encode
        df = df[df['label'].isin(self.label_map.keys())]
        df['target'] = df['label'].map(self.label_map)
        
        return df

    def train(self):
        full_df = self.load_and_preprocess()
        
        from .feature_extractor import FeatureExtractor
        extractor = FeatureExtractor()
        
        logger.info("Extracting combined features for training...")
        feature_list = []
        texts = []
        
        for _, row in full_df.iterrows():
            subj = str(row.get('subject', ''))
            body = str(row.get('body', ''))
            sender = str(row.get('sender', ''))
            feats = extractor.extract_features(subj, body, sender, "", [])
            texts.append(feats.pop('combined_text'))
            feats.pop('sender_domain')
            feature_list.append(feats)

        # 1. TF-IDF
        logger.info("Vectorizing text...")
        vectorizer = TfidfVectorizer(max_features=5000, stop_words='english', ngram_range=(1, 2))
        tfidf_matrix = vectorizer.fit_transform(texts)
        tfidf_df = pd.DataFrame(tfidf_matrix.toarray(), columns=vectorizer.get_feature_names_out())
        
        # 2. Combine with Metadata
        meta_df = pd.DataFrame(feature_list)
        X = pd.concat([meta_df, tfidf_df], axis=1)
        y = full_df['target'].values

        logger.info(f"Final feature shape: {X.shape}")
        
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.20, random_state=42, stratify=y
        )

        # 3. XGBoost Classifier (Phishing)
        logger.info("Training XGBoost Phishing Classifier...")
        model_phish = xgb.XGBClassifier(
            n_estimators=100,
            max_depth=6,
            learning_rate=0.1,
            objective='multi:softprob',
            num_class=3,
            eval_metric='mlogloss',
            random_state=42
        )
        model_phish.fit(X_train, y_train)

        # 4. Save Phishing Model
        joblib.dump(model_phish, os.path.join(self.models_dir, 'phishing_model.pkl'))
        joblib.dump(vectorizer, os.path.join(self.models_dir, 'vectorizer.pkl'))
        
        # --- PHASE 2: Category Model ---
        # We need the rich synthetic dataset for categories
        from .dataset_builder import DatasetBuilder
        builder = DatasetBuilder()
        from .category_classifier import CategoryClassifier
        
        cat_df = builder.build_unified_dataset()
        
        cat_feature_list = []
        cat_texts = []
        for _, row in cat_df.iterrows():
            feats = extractor.extract_features(row['subject'], row['body'], row['sender'], "", [])
            cat_texts.append(feats.pop('combined_text'))
            feats.pop('sender_domain')
            cat_feature_list.append(feats)
            
        vectorizer_cat = TfidfVectorizer(max_features=5000, stop_words='english', ngram_range=(1, 2))
        tfidf_cat = vectorizer_cat.fit_transform(cat_texts)
        tfidf_cat_df = pd.DataFrame(tfidf_cat.toarray(), columns=vectorizer_cat.get_feature_names_out())
        X_cat = pd.concat([pd.DataFrame(cat_feature_list), tfidf_cat_df], axis=1)
        
        cat_to_id = {c: i for i, c in enumerate(CategoryClassifier.CATEGORIES)}
        y_cat = np.array([cat_to_id.get(c, cat_to_id['UNKNOWN']) for c in cat_df['category']])
        
        logger.info("Training XGBoost Category Classifier...")
        model_cat = xgb.XGBClassifier(
            n_estimators=100,
            max_depth=6,
            learning_rate=0.1,
            objective='multi:softprob',
            num_class=len(CategoryClassifier.CATEGORIES),
            eval_metric='mlogloss',
            random_state=42
        )
        model_cat.fit(X_cat, y_cat)
        
        joblib.dump(model_cat, os.path.join(self.models_dir, 'category_model.pkl'))
        joblib.dump(vectorizer_cat, os.path.join(self.models_dir, 'vectorizer_cat.pkl'))

        logger.info("All models trained and saved.")

def train_models():
    trainer = PhishingModelTrainer()
    trainer.train()

if __name__ == "__main__":
    train_models()
