import tldextract

SUSPICIOUS_KEYWORDS = ["login", "verify", "secure", "update", "account"]

def extract_domain(url):
    ext = tldextract.extract(url)
    return f"{ext.domain}.{ext.suffix}"

def find_suspicious_keywords(text):
    found = []
    text = text.lower()
    
    for word in SUSPICIOUS_KEYWORDS:
        if word in text:
            found.append(word)
    
    return found