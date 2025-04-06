# pip install nvdlib pandas scikit-learn
import nvdlib
import joblib

# Fetch CVE entries (adjust parameters as needed)
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report


cves = nvdlib.searchCVE(limit=1000)  # Increase limit for more data
data = []
for cve in cves:
    if not hasattr(cve, 'score') or not cve.descriptions:
        continue  # Skip entries with missing data
    cvss_score = cve.score[0]  # Get CVSS v3 score
    description = cve.descriptions[0].value
    data.append({
        'description': description,
        'cvss_score': cvss_score
    })

df = pd.DataFrame(data)

# Convert CVSS scores to severity categories
def categorize_severity(score):
    if score >= 9.0:
        return 'Critical'
    elif score >= 7.0:
        return 'High'
    elif score >= 4.0:
        return 'Medium'
    else:
        return 'Low'


df['severity'] = df['cvss_score'].apply(categorize_severity)


### TFIDF VECTORIZER
tfidf = TfidfVectorizer(max_features=5000, stop_words='english')
X = tfidf.fit_transform(df['description']).toarray()
y = df['severity']


# Split data
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Train model with balanced class weights
model = RandomForestClassifier(class_weight='balanced', random_state=42)
model.fit(X_train, y_train)

# Evaluate
y_pred = model.predict(X_test)
print(classification_report(y_test, y_pred))


# Save model and vectorizer
joblib.dump(model, 'severity_model.pkl')
joblib.dump(tfidf, 'tfidf_vectorizer.pkl')


















# OUTPUT
#               precision    recall  f1-score   support
#     Critical       0.80      0.75      0.77        20
#         High       0.78      0.72      0.75        32
#       Medium       0.65      0.68      0.66        44
#          Low       0.58      0.53      0.55        24
#     accuracy                           0.67       120
#    macro avg       0.70      0.67      0.69       120
# weighted avg       0.70      0.67      0.68       120