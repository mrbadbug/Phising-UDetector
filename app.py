import streamlit as st
import pandas as pd
import pickle
from pathlib import Path

from feature_extractor import extract_basic_features

st.set_page_config(page_title="Phishing URL Detector", layout="centered")
st.title("Phishing URL Detector 🔒")

# Load model
model_path = "phishing_model.pkl"
if not Path(model_path).exists():
    st.error(f"Model file '{model_path}' not found!")
    st.stop()

with open(model_path, "rb") as f:
    model = pickle.load(f)

# Select mode
mode = st.radio("Mode", ["Single URL", "Batch CSV"])

# Single URL
if mode == "Single URL":
    url = st.text_input("Enter URL to check")
    if st.button("Predict URL"):
        if url:
            try:
                features = pd.DataFrame([extract_basic_features(url)])
                prediction = model.predict(features)[0]
                result = "Phishing ⚠️" if prediction == 1 else "Legitimate ✅"
                st.success(f"Prediction for '{url}': {result}")
            except Exception as e:
                st.error(f"Failed to predict URL: {e}")
        else:
            st.warning("Please enter a URL.")

# Batch CSV
elif mode == "Batch CSV":
    uploaded_file = st.file_uploader("Upload CSV with a column named 'url'", type=["csv"])
    if uploaded_file:
        try:
            df = pd.read_csv(uploaded_file)
            if "url" not in df.columns:
                st.error("CSV must have a column named 'url'.")
            else:
                features_list = [extract_basic_features(u) for u in df["url"]]
                features_df = pd.DataFrame(features_list)
                predictions = model.predict(features_df)
                df["prediction"] = ["Phishing ⚠️" if p==1 else "Legitimate ✅" for p in predictions]
                st.dataframe(df)
                st.download_button(
                    label="Download Results",
                    data=df.to_csv(index=False).encode('utf-8'),
                    file_name="phishing_predictions.csv",
                    mime="text/csv"
                )
        except Exception as e:
            st.error(f"Failed to process CSV: {e}")
