import tldextract

SUSPICIOUS_WORDS = [
    "login", "secure", "update", "verify", "account", "bank", "paypal", "ebay", "confirm"
]

def extract_basic_features(url: str) -> dict:
    """
    Extracts basic phishing features from a URL.
    Returns a dictionary with features expected by your ML model.
    """
    features = {}
    
    # URL length
    features['url_length'] = len(url)
    
    # Count dots
    features['count_dots'] = url.count('.')
    
    # @ symbol presence
    features['has_at'] = int('@' in url)
    
    # HTTPS presence
    features['has_https'] = int(url.lower().startswith("https"))
    
    # Count subdirectories
    path = url.split("//")[-1].split("/", 1)
    features['count_subdirs'] = url.count('/') - 2 if len(path) > 1 else 0
    
    # Suspicious words
    features['suspicious_word_count'] = sum(word in url.lower() for word in SUSPICIOUS_WORDS)
    
    # Query parameters
    features['count_queries'] = url.count('?')
    
    # TLD length
    ext = tldextract.extract(url)
    features['tld_length'] = len(ext.suffix)
    
    return features

