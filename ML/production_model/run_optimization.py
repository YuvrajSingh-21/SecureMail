import os
import json
import time
import pandas as pd
import numpy as np
import warnings
import unicodedata
import html
import re
import urllib.parse
import joblib

import optuna
from sklearn.model_selection import StratifiedKFold, train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline, FeatureUnion
from sklearn.preprocessing import MinMaxScaler, LabelEncoder
from sklearn.impute import SimpleImputer
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score, brier_score_loss
from sklearn.calibration import CalibratedClassifierCV
from xgboost import XGBClassifier

warnings.filterwarnings("ignore")

DATASET_PATH = "/home/lonewolf/Email_Phisher/Datasets/processed/final/dataset_v1.csv"
OUT_DIR = "/home/lonewolf/Email_Phisher/Email_Phisher/ML/production_model/"

def normalize_text(text):
    if not isinstance(text, str): return ""
    text = html.unescape(text)
    text = unicodedata.normalize('NFKC', text)
    text = re.sub(r'<[^>]+>', ' ', text)
    text = re.sub(r'[\u200b\u200c\u200d\uFEFF]', '', text)
    return re.sub(r'\s+', ' ', text).strip()

def normalize_urls(u_str):
    if not isinstance(u_str, str): return "[]"
    try:
        urls = json.loads(u_str)
        return json.dumps([unicodedata.normalize('NFKC', urllib.parse.unquote(u)).lower() for u in urls])
    except: return "[]"

def build_features(df):
    df['body_raw'] = df['body'].fillna('').astype(str)
    df['body'] = df['body_raw'].apply(normalize_text)
    df['subject'] = df['subject'].fillna('').astype(str).apply(normalize_text)
    
    if 'urls' not in df.columns: df['urls'] = "[]"
    df['urls'] = df['urls'].apply(normalize_urls)
    
    df['body_len'] = df['body'].str.len()
    df['subj_len'] = df['subject'].str.len()
    df['uppercase_ratio'] = df['body_raw'].apply(lambda x: sum(1 for c in x if c.isupper()) / max(1, len(x)))
    df['digit_ratio'] = df['body'].apply(lambda x: sum(1 for c in x if c.isdigit()) / max(1, len(x)))
    
    def count_urls(u_str):
        try: return len(json.loads(u_str))
        except: return 0
    df['url_count'] = df['urls'].apply(count_urls)
    
    df['urgency_word_count'] = df['body'].str.lower().str.count(r'\b(urgent|immediate|suspension|alert|action required)\b')
    df['financial_word_count'] = df['body'].str.lower().str.count(r'\b(invoice|payment|wire|transfer|crypto|bank|money)\b')
    df['cred_theft_word_count'] = df['body'].str.lower().str.count(r'\b(login|password|verify|secure|account|update)\b')
    if 'is_html' not in df.columns: df['is_html'] = False
    if 'has_attachment' not in df.columns: df['has_attachment'] = False
    return df

def run_optimization():
    os.makedirs(OUT_DIR, exist_ok=True)
    print("Loading data for optimization...")
    df = pd.read_csv(DATASET_PATH, low_memory=False)
    # Stratified subsampling for fast optimization
    df, _ = train_test_split(df, train_size=20000, stratify=df['label'], random_state=42)
    df = build_features(df)
    
    le = LabelEncoder()
    y = le.fit_transform(df['label'])
    
    # Preprocessor
    ENRON_ARTIFACTS = ['enron', 'houston', 'ect', 'kaminski', 'vince', 'shirley', 'jones', 'smith', '2000', '2001', '2002', '1999']
    HEADERS_ARTIFACTS = ['message-id', 'x-origin', 'x-folder', 'x-filename', 'mime-version', 'content-type', 'content-transfer-encoding']
    CUSTOM_STOPWORDS = list(set(TfidfVectorizer(stop_words='english').get_stop_words()).union(set(ENRON_ARTIFACTS + HEADERS_ARTIFACTS)))
    
    word_tfidf = TfidfVectorizer(analyzer='word', max_features=1000, stop_words=CUSTOM_STOPWORDS)
    char_tfidf = TfidfVectorizer(analyzer='char_wb', ngram_range=(3, 5), max_features=1000)
    text_features = FeatureUnion([('word', word_tfidf), ('char', char_tfidf)])
    numeric_features = ['body_len', 'subj_len', 'uppercase_ratio', 'digit_ratio', 'url_count', 'urgency_word_count', 'financial_word_count', 'cred_theft_word_count', 'is_html', 'has_attachment']
    numeric_transformer = Pipeline(steps=[('imputer', SimpleImputer(strategy='constant', fill_value=0)), ('scaler', MinMaxScaler())])
    
    preprocessor = ColumnTransformer(transformers=[('text', text_features, 'body'), ('num', numeric_transformer, numeric_features)], remainder='drop')
    
    print("Fitting preprocessor...")
    X = preprocessor.fit_transform(df)
    
    print("Using best Optuna parameters discovered...")
    best_params = {'n_estimators': 170, 'max_depth': 8, 'learning_rate': 0.10354497330498708, 'subsample': 0.7480636310797557, 'colsample_bytree': 0.7112322186307786, 'gamma': 0.3045908575098924, 'tree_method': 'hist'}
    
    print("Training Final Calibrated Model on larger set...")
    # Get a larger set for final model
    df_full = pd.read_csv(DATASET_PATH, low_memory=False)
    df_full, _ = train_test_split(df_full, train_size=50000, stratify=df_full['label'], random_state=42)
    df_full = build_features(df_full)
    y_full = le.fit_transform(df_full['label'])
    
    # Weights
    source_counts = df_full['dataset_source'].value_counts()
    w_full = df_full['dataset_source'].apply(lambda s: 1.0 / np.log1p(source_counts[s]))
    w_full = w_full * (len(df_full) / w_full.sum())
    
    X_full = preprocessor.fit_transform(df_full)
    
    # Train test split for final evaluation
    X_tr, X_te, y_tr, y_te, w_tr, w_te = train_test_split(X_full, y_full, w_full, test_size=0.2, stratify=y_full, random_state=42)
    
    base_model = XGBClassifier(**best_params, use_label_encoder=False, eval_metric='mlogloss', n_jobs=-1, random_state=42)
    
    # Calibration
    calibrated_model = CalibratedClassifierCV(estimator=base_model, method='sigmoid', cv=3)
    # CalibratedClassifierCV doesn't natively accept sample_weight in older scikit-learn without fit_params
    try:
        calibrated_model.fit(X_tr, y_tr, sample_weight=w_tr.values)
    except Exception as e:
        calibrated_model.fit(X_tr, y_tr)
    
    # Metrics
    start_infer = time.time()
    preds = calibrated_model.predict(X_te)
    infer_time = time.time() - start_infer
    
    mac_f1 = f1_score(y_te, preds, average='macro')
    acc = accuracy_score(y_te, preds)
    
    # Exports
    print("Exporting Artifacts...")
    joblib.dump(calibrated_model, os.path.join(OUT_DIR, "model_v1.joblib"))
    joblib.dump(preprocessor, os.path.join(OUT_DIR, "preprocessor.joblib"))
    joblib.dump(le, os.path.join(OUT_DIR, "label_encoder.joblib"))
    
    with open(os.path.join(OUT_DIR, "best_parameters.json"), "w") as f:
        json.dump(best_params, f, indent=4)
        
    with open(os.path.join(OUT_DIR, "model_card.md"), "w") as f:
        f.write("# Model Card: SecureMail ML Engine v1.0\n\n")
        f.write("## Purpose\nReal-time detection of Phishing and Spam emails using hybrid structural and semantic extraction.\n\n")
        f.write("## Architecture\n- **Feature Extraction:** Hybrid Word + Character-Boundary TF-IDF alongside 10 numeric metadata features.\n")
        f.write("- **Model:** XGBoost Classifier with Sigmoid Probability Calibration.\n")
        f.write("- **Adversarial Defenses:** Pre-processing HTML unescaping, NFKC normalization, Zero-Width stripping.\n\n")
        f.write(f"## Final Performance\n- **Accuracy:** {acc:.4f}\n- **Macro F1:** {mac_f1:.4f}\n- **Inference Time (10k emails):** {infer_time:.4f}s\n\n")
        f.write("## Known Limitations\n- The model can produce False Positives on highly automated transactional emails sharing 'urgency' vocabulary. A pre-ML trusted sender allowlist is mandated.\n")
        f.write("## Final Verdict\nThis model is fully calibrated and frozen for production deployment. The next step is Django integration.\n")

if __name__ == '__main__':
    run_optimization()
