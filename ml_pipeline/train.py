import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from xgboost import XGBClassifier
from sklearn.metrics import classification_report, accuracy_score
from imblearn.over_sampling import SMOTE
import joblib
import os

drebin_path = r"c:\hybrid ids\dataset\drebin.csv"
cic_static_path = r"c:\hybrid ids\dataset\CICMalDroid 2020\feature_vectors_static.csv"
cic_dynamic_path = r"c:\hybrid ids\dataset\CICMalDroid 2020\feature_vectors_syscalls_frequency_5_Cat.csv"

def train_static_model():
    print("Loading Drebin dataset...")
    # Drebin usually has 'class' column with 'B' (Benign) and 'S' (Malware/Smali)
    drebin_df = pd.read_csv(drebin_path)
    
    # We will use Drebin first to train a basic static model. 
    # Combining it with CICMalDroid static features requires matching columns, which can be complex.
    # Let's train on Drebin for now as our primary Static Model.
    print(f"Drebin Shape: {drebin_df.shape}")
    
    # Preprocess
    # Replace '?' with NaN and fill with 0
    drebin_df = drebin_df.replace('?', np.nan)
    drebin_df = drebin_df.fillna(0)
    
    if 'class' in drebin_df.columns:
        y = drebin_df['class'].apply(lambda x: 1 if x == 'S' else 0)
        X = drebin_df.drop('class', axis=1)
    else:
        print("Class column not found in Drebin.")
        return

    # Ensure all columns are numeric
    X = X.apply(pd.to_numeric, errors='coerce').fillna(0)

    # Train Test Split
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    # Apply SMOTE to handle class imbalance
    smote = SMOTE(random_state=42)
    X_train, y_train = smote.fit_resample(X_train, y_train)
    
    print("Training Static Model (XGBoost with SMOTE)...")
    clf = XGBClassifier(n_estimators=500, max_depth=8, learning_rate=0.05, subsample=0.8, colsample_bytree=0.8, n_jobs=-1, random_state=42)
    clf.fit(X_train, y_train)
    
    # Evaluate
    preds = clf.predict(X_test)
    print("--- Static Model Evaluation ---")
    print(f"Accuracy: {accuracy_score(y_test, preds):.4f}")
    print(classification_report(y_test, preds))
    
    # Save
    os.makedirs('models', exist_ok=True)
    joblib.dump(clf, 'models/static_rf_model.pkl')
    # Save the feature columns for the backend to use later
    joblib.dump(list(X.columns), 'models/static_features.pkl')
    print("Static model saved to models/static_rf_model.pkl")

def train_dynamic_model():
    print("Loading CICMalDroid Dynamic dataset...")
    # This dataset usually has 5 categories (Adware, Banking, Riskware, SMS, Benign)
    df = pd.read_csv(cic_dynamic_path)
    print(f"Dynamic Shape: {df.shape}")
    
    df = df.replace('?', np.nan)
    df = df.fillna(0)
    
    # The label column is usually 'Class' in CICMalDroid
    label_col = 'Class' if 'Class' in df.columns else 'class'
    
    if label_col in df.columns:
        # Convert multi-class to binary (Benign = 5.0, Malware = others)
        y = df[label_col].apply(lambda x: 0 if x == 5.0 else 1)
        X = df.drop(label_col, axis=1)
    else:
        print("Label column not found in dynamic dataset.")
        return
        
    X = X.apply(pd.to_numeric, errors='coerce').fillna(0)
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    # Apply SMOTE
    smote = SMOTE(random_state=42)
    X_train, y_train = smote.fit_resample(X_train, y_train)
    
    print("Training Dynamic Model (XGBoost with SMOTE)...")
    clf = XGBClassifier(n_estimators=500, max_depth=8, learning_rate=0.05, subsample=0.8, colsample_bytree=0.8, n_jobs=-1, random_state=42)
    clf.fit(X_train, y_train)
    
    # Evaluate
    preds = clf.predict(X_test)
    print("--- Dynamic Model Evaluation ---")
    print(f"Accuracy: {accuracy_score(y_test, preds):.4f}")
    print(classification_report(y_test, preds))
    
    # Save
    os.makedirs('models', exist_ok=True)
    joblib.dump(clf, 'models/dynamic_rf_model.pkl')
    joblib.dump(list(X.columns), 'models/dynamic_features.pkl')
    print("Dynamic model saved to models/dynamic_rf_model.pkl")

if __name__ == "__main__":
    train_static_model()
    train_dynamic_model()
    print("ML Pipeline Phase 1 Complete.")
