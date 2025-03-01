from flask import Flask, request, jsonify
import joblib
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer

# Load the trained model and preprocessing tools
model = joblib.load("nvd_risk_classifier.pkl")
label_encoder = joblib.load("cwe_label_encoder.pkl")
tfidf_vectorizer = joblib.load("tfidf_vectorizer.pkl")

app = Flask(__name__)

@app.route('/predict', methods=['POST'])
def predict():
    data = request.json
    if not data:
        return jsonify({"error": "Invalid request. No JSON data received."}), 400
    
    description = data.get("Description", "").strip()
    cvss_score = data.get("CVSS_Score", None)
    cwe = data.get("CWE", "Unknown CWE").strip()

    # Validate CVSS Score
    try:
        cvss_score = float(cvss_score)
    except (TypeError, ValueError):
        return jsonify({"error": "Invalid CVSS_Score. Must be a number."}), 400

    # Ensure CWE exists in label encoder
    if cwe not in list(label_encoder.classes_):
        return jsonify({"error": f"CWE '{cwe}' not recognized. Use a valid CWE."}), 400

    # Encode CWE
    cwe_encoded = label_encoder.transform([cwe])[0]

    # Ensure non-empty description
    if not description:
        description = "No description available"

    # Transform description using TF-IDF
    tfidf_features = tfidf_vectorizer.transform([description]).toarray()

    # Combine features
    X_input = np.hstack(([cvss_score, cwe_encoded], tfidf_features[0]))

    # Make prediction (Ensure correct shape)
    prediction = model.predict(np.array([X_input]))[0]

    return jsonify({"Predicted_Risk_Level": prediction})

@app.route('/predict_bulk', methods=['POST'])
def predict_bulk():
    data = request.json
    if not isinstance(data, list):
        return jsonify({"error": "Invalid request. Expecting a list of JSON objects."}), 400

    results = []
    for entry in data:
        description = entry.get("Description", "").strip()
        cvss_score = entry.get("CVSS_Score", None)
        cwe = entry.get("CWE", "Unknown CWE").strip()

        # Validate CVSS Score
        try:
            cvss_score = float(cvss_score)
        except (TypeError, ValueError):
            results.append({"error": "Invalid CVSS_Score. Must be a number."})
            continue

        # Ensure CWE exists in label encoder
        if cwe not in list(label_encoder.classes_):
            results.append({"error": f"CWE '{cwe}' not recognized. Use a valid CWE."})
            continue

        # Encode CWE
        cwe_encoded = label_encoder.transform([cwe])[0]

        # Ensure non-empty description
        if not description:
            description = "No description available"

        # Transform description using TF-IDF
        tfidf_features = tfidf_vectorizer.transform([description]).toarray()

        # Combine features
        X_input = np.hstack(([cvss_score, cwe_encoded], tfidf_features[0]))

        # Make prediction
        prediction = model.predict(np.array([X_input]))[0]

        # Store results
        results.append({
            "Description": description,
            "CVSS_Score": cvss_score,
            "CWE": cwe,
            "Predicted_Risk_Level": prediction
        })

    return jsonify(results)

if __name__ == '__main__':
    app.run(debug=True, port=5000)  # Explicitly define port
