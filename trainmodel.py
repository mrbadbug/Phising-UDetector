#Install dependencies
!pip install pandas scikit-learn tldextract

#Imports
import pandas as pd
import tldextract
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import classification_report, accuracy_score
import pickle

#Feature extraction
SUSPICIOUS_WORDS = [
    "login", "secure", "update", "verify", "account", "bank", "paypal", "ebay", "confirm"
]

def extract_basic_features(url: str) -> dict:
    features = {}
    features['url_length'] = len(url)
    features['count_dots'] = url.count('.')
    features['has_at'] = int('@' in url)
    features['has_https'] = int(url.lower().startswith("https"))
    path = url.split("//")[-1].split("/", 1)
    features['count_subdirs'] = url.count('/') - 2 if len(path) > 1 else 0
    features['suspicious_word_count'] = sum(word in url.lower() for word in SUSPICIOUS_WORDS)
    features['count_queries'] = url.count('?')
    ext = tldextract.extract(url)
    features['tld_length'] = len(ext.suffix)
    return features

#Sample dataset (replace with your CSV if you have one)
data = [
    ("http://secure-login-verify-paypal.com", 1),
    ("https://www.google.com", 0),
    ("http://update-account-paypal.com", 1),
    ("https://www.github.com", 0),
    ("http://login-bank-secure.com", 1),
    ("https://www.stackoverflow.com", 0),
]

df = pd.DataFrame(data, columns=["url", "label"])

#Extract features
features_list = [extract_basic_features(url) for url in df["url"]]
X = pd.DataFrame(features_list)
y = df["label"]

#Train/test split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

#Train model
model = DecisionTreeClassifier()
model.fit(X_train, y_train)

#Evaluate
y_pred = model.predict(X_test)
print("Accuracy:", accuracy_score(y_test, y_pred))
print(classification_report(y_test, y_pred))

#Save model
with open("phishing_model.pkl", "wb") as f:
    pickle.dump(model, f)

print("Model saved as phishing_model.pkl ✅")

#Test single URL prediction
sample_url = "http://secure-login-verify-paypal.com"
sample_features = pd.DataFrame([extract_basic_features(sample_url)])
prediction = model.predict(sample_features)[0]
print(f"Prediction for '{sample_url}': {'Phishing' if prediction == 1 else 'Legitimate'}")