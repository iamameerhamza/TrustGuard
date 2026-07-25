import os
import sys
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
import joblib
import csv

# We are using csv to load instead of pandas to keep dependencies light, but since we just installed scikit-learn,
# let's just use standard csv and convert to lists, then feed to sklearn to avoid adding pandas dependency explicitly if not needed.
# Actually, the user asked if they should add pandas. We stuck to the ponytail rule. So let's load data with csv.

def load_data(filepath):
    features = []
    labels = []
    feature_names = ["url_length", "domain_length", "subdomain_count", "has_special_chars", "entropy", "suspicious_keywords"]
    
    with open(filepath, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            labels.append(int(row['label']))
            features.append([
                float(row['url_length']),
                float(row['domain_length']),
                float(row['subdomain_count']),
                1.0 if row['has_special_chars'] == 'True' else 0.0,
                float(row['entropy']),
                float(row['suspicious_keywords'])
            ])
    return features, labels, feature_names

def main():
    data_path = "data/dataset.csv"
    model_dir = "models"
    model_path = os.path.join(model_dir, "phishing_rf.joblib")
    
    os.makedirs(model_dir, exist_ok=True)
    
    print(f"Loading data from {data_path}...")
    X, y, feature_names = load_data(data_path)
    
    print("Splitting dataset into train and test sets (80/20)...")
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    
    print("Training Random Forest Classifier (100 trees)...")
    clf = RandomForestClassifier(n_estimators=100, random_state=42)
    clf.fit(X_train, y_train)
    
    print("Evaluating model...")
    y_pred = clf.predict(X_test)
    
    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred)
    recall = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    cm = confusion_matrix(y_test, y_pred)
    
    print("\n--- Model Evaluation Metrics ---")
    print(f"Accuracy:  {accuracy:.4f}")
    print(f"Precision: {precision:.4f}")
    print(f"Recall:    {recall:.4f}")
    print(f"F1 Score:  {f1:.4f}")
    print(f"Confusion Matrix:\n{cm}")
    
    print(f"\nSaving trained model to {model_path}...")
    joblib.dump(clf, model_path)
    print("Model saved successfully!")

if __name__ == "__main__":
    main()
