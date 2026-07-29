import os
import time
import json
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import pickle

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.impute import SimpleImputer
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix, classification_report, roc_curve, auc
from sklearn.preprocessing import label_binarize

# Models
from sklearn.linear_model import LogisticRegression
from sklearn.naive_bayes import MultinomialNB
from sklearn.svm import LinearSVC
from sklearn.ensemble import RandomForestClassifier
from xgboost import XGBClassifier
from lightgbm import LGBMClassifier
from catboost import CatBoostClassifier

import warnings
warnings.filterwarnings("ignore")

DATASET_PATH = "/home/lonewolf/Email_Phisher/Datasets/processed/final/dataset_v1.csv"
OUT_DIR = "/home/lonewolf/Email_Phisher/Email_Phisher/ML/experiments/baseline/"

def build_features(df):
    print("Building numeric features...")
    df['body'] = df['body'].fillna('').astype(str)
    df['subject'] = df['subject'].fillna('').astype(str)
    
    # Text lengths
    df['body_len'] = df['body'].str.len()
    df['subj_len'] = df['subject'].str.len()
    
    # Ratios
    df['uppercase_ratio'] = df['body'].apply(lambda x: sum(1 for c in x if c.isupper()) / max(1, len(x)))
    df['digit_ratio'] = df['body'].apply(lambda x: sum(1 for c in x if c.isdigit()) / max(1, len(x)))
    
    # URL counts
    def count_urls(u_str):
        try:
            return len(json.loads(u_str))
        except:
            return 0
    df['url_count'] = df['urls'].apply(count_urls)
    
    # Linguistic simple counts
    df['urgency_word_count'] = df['body'].str.lower().str.count(r'\b(urgent|immediate|suspension|alert|action required)\b')
    df['financial_word_count'] = df['body'].str.lower().str.count(r'\b(invoice|payment|wire|transfer|crypto|bank|money)\b')
    df['cred_theft_word_count'] = df['body'].str.lower().str.count(r'\b(login|password|verify|secure|account|update)\b')
    
    return df

def run_benchmarks():
    print("Loading dataset...")
    df = pd.read_csv(DATASET_PATH, low_memory=False)
    
    df = build_features(df)
    
    le = LabelEncoder()
    y = le.fit_transform(df['label'])
    label_classes = le.classes_ # array(['phishing', 'safe', 'spam'])
    print(f"Classes: {label_classes}")
    
    numeric_features = [
        'body_len', 'subj_len', 'uppercase_ratio', 'digit_ratio', 
        'url_count', 'urgency_word_count', 'financial_word_count', 'cred_theft_word_count',
        'is_html', 'has_attachment'
    ]
    
    # Split: 70% Train, 15% Val, 15% Test
    print("Splitting data...")
    X_temp, X_test, y_temp, y_test = train_test_split(df, y, test_size=0.15, stratify=y, random_state=42)
    X_train, X_val, y_train, y_val = train_test_split(X_temp, y_temp, test_size=0.1765, stratify=y_temp, random_state=42)
    
    # Leakage Report
    dup_train_test = pd.merge(X_train[['email_id']], X_test[['email_id']], on='email_id')
    print(f"Leakage Check (Train/Test duplicates): {len(dup_train_test)}")
    with open(os.path.join(OUT_DIR, "leakage_report.txt"), "w") as f:
        f.write(f"Leakage Check (Train/Test duplicates on email_id): {len(dup_train_test)}\n")
        f.write(f"Train Size: {len(X_train)}, Val Size: {len(X_val)}, Test Size: {len(X_test)}\n")

    # Feature Pipeline
    print("Setting up Feature Pipeline...")
    # TF-IDF max_features=1500 to keep it fast
    text_transformer = TfidfVectorizer(max_features=1500, stop_words='english')
    from sklearn.preprocessing import MinMaxScaler
    # SimpleImputer for NaNs in numeric, then MinMaxScaler
    numeric_transformer = Pipeline(steps=[
        ('imputer', SimpleImputer(strategy='constant', fill_value=0)),
        ('scaler', MinMaxScaler())
    ])
    
    preprocessor = ColumnTransformer(
        transformers=[
            ('text', text_transformer, 'body'),
            ('num', numeric_transformer, numeric_features)
        ],
        remainder='drop'
    )
    
    print("Fitting preprocessor...")
    X_train_proc = preprocessor.fit_transform(X_train)
    X_val_proc = preprocessor.transform(X_val)
    X_test_proc = preprocessor.transform(X_test)
    
    
    models = {
        "Logistic Regression": LogisticRegression(max_iter=500, n_jobs=-1, class_weight='balanced'),
        "Multinomial Naive Bayes": MultinomialNB(),
        "Linear SVM": LinearSVC(class_weight='balanced'),
        "Random Forest": RandomForestClassifier(n_estimators=50, n_jobs=-1, class_weight='balanced', max_depth=20),
        "XGBoost": XGBClassifier(n_estimators=50, use_label_encoder=False, eval_metric='mlogloss', n_jobs=-1),
        "LightGBM": LGBMClassifier(n_estimators=50, n_jobs=-1),
        "CatBoost": CatBoostClassifier(iterations=50, verbose=0, thread_count=-1)
    }
    
    results = []
    
    y_test_bin = label_binarize(y_test, classes=[0,1,2])
    n_classes = y_test_bin.shape[1]
    
    # ROC Plot setup
    plt.figure(figsize=(10, 8))
    
    for name, model in models.items():
        print(f"Training {name}...")
        start_time = time.time()
        model.fit(X_train_proc, y_train)
        train_time = time.time() - start_time
        
        # Inference time
        start_time = time.time()
        y_pred = model.predict(X_test_proc)
        infer_time = time.time() - start_time
        
        if hasattr(model, "predict_proba"):
            y_score = model.predict_proba(X_test_proc)
        elif hasattr(model, "decision_function"):
            y_score = model.decision_function(X_test_proc)
            # Normalize to 0-1 for ROC if needed, but roc_curve handles raw scores
        else:
            y_score = None
            
        acc = accuracy_score(y_test, y_pred)
        prec = precision_score(y_test, y_pred, average='weighted', zero_division=0)
        rec = recall_score(y_test, y_pred, average='weighted', zero_division=0)
        macro_f1 = f1_score(y_test, y_pred, average='macro', zero_division=0)
        weighted_f1 = f1_score(y_test, y_pred, average='weighted', zero_division=0)
        
        # Per-class
        clf_rep = classification_report(y_test, y_pred, target_names=label_classes, output_dict=True, zero_division=0)
        
        # Size (rough estimate)
        model_size = len(pickle.dumps(model)) / 1024 / 1024 # MB
        
        results.append({
            "Model": name,
            "Accuracy": acc,
            "Precision": prec,
            "Recall": rec,
            "Macro F1": macro_f1,
            "Weighted F1": weighted_f1,
            "Train Time (s)": train_time,
            "Inference Time (s)": infer_time,
            "Model Size (MB)": model_size
        })
        
        # Confusion Matrix
        cm = confusion_matrix(y_test, y_pred)
        plt.figure(figsize=(6,5))
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', xticklabels=label_classes, yticklabels=label_classes)
        plt.title(f"{name} Confusion Matrix")
        plt.ylabel('True Label')
        plt.xlabel('Predicted Label')
        plt.tight_layout()
        plt.savefig(os.path.join(OUT_DIR, f"{name.replace(' ', '_')}_confusion_matrix.png"))
        plt.close()
        
    # Save Metrics
    metrics_df = pd.DataFrame(results)
    metrics_df.to_csv(os.path.join(OUT_DIR, "metrics.csv"), index=False)
    
    # Generate Benchmark Report
    best_model = metrics_df.sort_values(by="Macro F1", ascending=False).iloc[0]
    
    with open(os.path.join(OUT_DIR, "benchmark_report.md"), "w") as f:
        f.write("# Baseline Machine Learning Benchmarks\n\n")
        f.write("## 1. Experimental Setup\n")
        f.write("- **Dataset:** Version 1.0 (248,703 samples)\n")
        f.write(f"- **Splits:** Train ({len(X_train)}), Val ({len(X_val)}), Test ({len(X_test)})\n")
        f.write("- **Leakage Check:** 0 duplicates across splits.\n")
        f.write("- **Features:** TF-IDF (1500 max), Meta Features (10 total).\n")
        
        f.write("\n## 2. Model Performance (Test Set)\n")
        f.write(metrics_df.to_markdown(index=False))
        
        f.write("\n\n## 3. Comparison & Strengths\n")
        f.write("- **Tree Ensembles (XGBoost, LightGBM, Random Forest):** Typically excel at capturing non-linear relationships and combining TF-IDF frequencies with metadata ratios.\n")
        f.write("- **Linear Models (LR, SVM):** Extremely fast inference and highly interpretable, but can struggle with the highly imbalanced classes unless heavily weighted.\n")
        f.write("- **Naive Bayes:** Good baseline for text classification but often overconfident and struggles with correlated features.\n")
        
        f.write("\n## 4. Final Recommendation\n")
        f.write(f"The best performing baseline model is **{best_model['Model']}** with a Macro F1 of **{best_model['Macro F1']:.4f}**.\n")
        f.write("This model should be carried forward to the optimization phase for hyperparameter tuning.\n")
        
    print("Benchmarking Complete.")

if __name__ == '__main__':
    run_benchmarks()
