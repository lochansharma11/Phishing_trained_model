import streamlit as st
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import os
import pickle
from urllib.parse import urlparse




# Streamlit App Configuration
st.set_page_config(
    page_title="PhishProtector",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.title("🛡️ PhishProtector - Stay Safe Online")
st.write("A cutting-edge tool to detect phishing websites and protect your digital presence.")

# Sidebar Navigation
st.sidebar.title("Navigation")
pages = st.sidebar.radio("Go to", ["Home", "Detect Phishing", "About"])

# Home Page
if pages == "Home":
    st.image("image/phishing-detection.png", use_container_width=True)
    st.markdown(
        """
        ## Why Choose PhishProtector?
        - 🔍 **Accurate Detection:** Powered by advanced AI and machine learning.
        - 🛡️ **Comprehensive Protection:** Analyze multiple features of a website.
        - 🌐 **Easy to Use:** Just enter a URL and let the tool do the work.
        
        ## Features
        - Real-time analysis of URLs
        - Detailed reports for suspicious websites
        - Secure and reliable
        """
    )



# Detect Phishing Page
elif pages == "Detect Phishing":
    st.header("🔗 Detect Phishing Websites")
    import pandas as pd
import numpy as np
import joblib
import streamlit as st
from urllib.parse import urlparse
import re

#Load the saved model
model = joblib.load('logistic_regression_model.pkl')

# Function to validate if the input is a URL
def is_valid_url(url):
    # Check if the input has a valid URL structure
    regex = re.compile(
        r'^(https?://)?'  # Optional scheme
        r'((([a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,})|'  # Domain name
        r'localhost|'  # localhost
        r'\d+\.\d+\.\d+\.\d+)'  # OR IPv4 address
        r'(:\d+)?'  # Optional port
        r'(/.*)?$'  # Optional path
    )
    return re.match(regex, url) is not None


# Feature extraction function
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


    

# Streamlit app
st.write("Enter a URL to check if it's phishing or legitimate.")


# Input for the URL
url_input = st.text_input("Enter a  Valid URL to check:")
if st.button("Check"):
    if url_input:
        if is_valid_url(url_input):
            # Extract features from the input URL
            features = pd.DataFrame([extract_features(url_input)])
            
            # Make prediction
            prediction = model.predict(features)[0]
            result = " ⚠ The website is **phishing**." if prediction == 1 else " ✅The website is **legitimate or safe to use**."
            
            # Display result
            st.write(f" **{result}**")
        else:
            st.write("Invalid URL format. Please enter a valid URL.")
    else:
        st.write("Please enter a valid URL.")



   


    



       
        







    

# Example Reports Section
st.markdown("### Example Reports")
st.image("image/url-phishing.webp", caption="Sample Analysis Report", use_container_width=True)

# About Page 

st.header("About PhishProtector")
st.write(
        """
        **PhishProtector** is a project aimed at reducing online threats by identifying phishing websites using machine learning.
        - Designed for users of all technical levels
        - Based on research and real-world datasets
        - Built with Python, Streamlit, and AI algorithms
        """
    )
st.markdown(
        """
        ### Technologies Used:
        - Python 🐍
        - Scikit-learn 🤖
        - Streamlit 🌟
        - Matplotlib & Seaborn 📊
        """
    )

# Sidebar Footer
st.sidebar.write("Developed by **Lochan Badahi**. © 2024 PhishProtector")


