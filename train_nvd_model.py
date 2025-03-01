import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import accuracy_score, classification_report
import joblib
import shap

# Load cleaned dataset
file_path = "/Users/vidushisingh/Downloads/AISecurityProject/nvd_vulnerability_data_clean.csv"
df = pd.read_csv(file_path)

# Check for missing values before processing
print("🔍 Checking for missing values before processing...")
print(df.isnull().sum())

# Drop rows where Risk_Level is NaN
df = df.dropna(subset=["Risk_Level"])

# Ensure CWE column has no missing values
df["CWE"] = df["CWE"].fillna("Unknown CWE")

# Encode categorical feature (CWE)
label_encoder = LabelEncoder()
df["CWE_Encoded"] = label_encoder.fit_transform(df["CWE"])

# Convert textual descriptions into TF-IDF features
tfidf_vectorizer = TfidfVectorizer(max_features=500)  # Limiting to 500 features to avoid overfitting
tfidf_features = tfidf_vectorizer.fit_transform(df["Description"]).toarray()

# Define Features (CVSS Score + CWE + TF-IDF of Description)
X_numeric = df[["CVSS_Score", "CWE_Encoded"]].values
X = np.hstack((X_numeric, tfidf_features))  # Combine numeric and textual features
y = df["Risk_Level"]

# Split data into Training (80%) & Testing (20%)
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

# Hyperparameter tuning using GridSearchCV
param_grid = {
    "n_estimators": [50, 100, 200],
    "max_depth": [5, 10, 20],
    "min_samples_split": [2, 5, 10],
    "min_samples_leaf": [1, 5, 10],
    "max_features": ["sqrt", "log2"]
}

rf = RandomForestClassifier(random_state=42)
grid_search = GridSearchCV(rf, param_grid, cv=5, n_jobs=-1, verbose=2)
grid_search.fit(X_train, y_train)

# Best model from GridSearch
best_rf = grid_search.best_estimator_

# Make predictions
y_pred = best_rf.predict(X_test)

# Evaluate model performance
accuracy = accuracy_score(y_test, y_pred)
print(f"✅ Best Model Accuracy: {accuracy:.2f}")
print("\n📊 Classification Report:\n", classification_report(y_test, y_pred))

# Save the trained model and encoders
joblib.dump(best_rf, "nvd_risk_classifier.pkl")
joblib.dump(label_encoder, "cwe_label_encoder.pkl")
joblib.dump(tfidf_vectorizer, "tfidf_vectorizer.pkl")
print("✅ Model and encoders saved successfully!")

# Interpretability using SHAP
explainer = shap.TreeExplainer(best_rf)
shap_values = explainer.shap_values(X_test[:100], check_additivity=False)
print("X_train shape:", X_train.shape)
print("X_test shape:", X_test.shape)


# Save SHAP values for later use
joblib.dump(shap_values, "shap_values.pkl")

print("📊 SHAP feature importance analysis completed!")
