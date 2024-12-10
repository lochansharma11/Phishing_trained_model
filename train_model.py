import pandas as pd
import re
from urllib.parse import urlparse
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report
import joblib
import numpy as np

# Step 1: Load the dataset
df = pd.read_csv('phishing_site_urls.csv')
df.columns = ['URL', 'Label']

# Step 2: Map "good" to 0 and "bad" to 1
df['Label'] = df['Label'].map({'good': 0, 'bad': 1})

# Step 3: Enhanced Feature Extraction
def extract_features(url):
    parsed_url = urlparse(url)
    netloc = parsed_url.netloc if parsed_url.netloc else parsed_url.path
    path = parsed_url.path
    domain = netloc.split('.')[0]  # Main domain
    tld = parsed_url.netloc.split('.')[-1]  # Top-level domain

    features = {
        'url_length': len(url),
        'num_subdomains': len(netloc.split('.')) - 1,
        'has_https': 1 if parsed_url.scheme == 'https' else 0,
        'has_ip': int(bool(re.match(r'\d+\.\d+\.\d+\.\d+', netloc))),
        'num_special_chars': sum(map(url.count, ['@', '//', '-', '_'])),
        'path_length': len(path),
        'num_query_params': len(parsed_url.query.split('&')) if parsed_url.query else 0,
        'suspicious_keywords': int(any(kw in url.lower() for kw in ['verify', 'secure', 'login', 'free', 'promo'])),
        'uncommon_tld': int(tld in ['xyz', 'top', 'club', 'cf', 'tk', 'work']),
        'has_numbers_in_domain': int(bool(re.search(r'\d', domain))),
        'entropy': -sum((p := np.array([url.count(char) / len(url) for char in set(url)])) * np.log2(p + 1e-10)),
        'is_generic_domain': int(len(domain) < 4),  # Detects short, possibly suspicious domain names
    }
    return features

# Step 4: Apply feature extraction
features = pd.DataFrame([extract_features(url) for url in df['URL']])
features['Label'] = df['Label']

# Step 5: Split into training and testing sets
X = features.drop(columns='Label')
y = features['Label']
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Step 6: Train the Logistic Regression model
model = LogisticRegression(max_iter=1000)
model.fit(X_train, y_train)

# Step 7: Evaluate the model
y_pred = model.predict(X_test)
print("Classification Report:\n")
print(classification_report(y_test, y_pred))

# Save the trained model
joblib.dump(model, 'logistic_regression_model.pkl')

# Debugging a specific case
test_url = "a.com"
test_features = pd.DataFrame([extract_features(test_url)])
test_prediction = model.predict(test_features)[0]
result = "Phishing" if test_prediction == 1 else "Legitimate"
print(f"Test URL: {test_url}\nPrediction: {result}")

from sklearn.model_selection import cross_val_score

scores = cross_val_score(model, X, y, cv=5)
print(f"Cross-validation scores: {scores}")

