import re
from urllib.parse import urlparse

def analyze_url(url):
    score = 0
    #check url length
    if len(url)>75:
        score += 1
    #ip check
    ip_pattern = r"(http|https)://\d+\.\d+\.\d+\.\d+"
    if re.match(ip_pattern, url):
        score += 2
    # count subdomains
    domain = urlparse(url).netloc
    if domain.count('.') > 3:
        score += 1
    
    #suspicious keywords
    suspicious_keywords = [
        'login', 
        'secure',
        'account', 
        'update',
        'free',
        'verify',
        'password',
        'bank',
        'confirm',
        'security'
    ]
    for keyword in suspicious_keywords:
        if keyword in url.lower():
            score += 1
            break
    return score

def classify(score):

    if score >= 3:
        return "Possibly phishing"
    else:
        return "Possibly legitimate"
url = input("Enter a URL to analyze: ")
score = analyze_url(url)
classification = classify(score)
print(f"URL: {url}")
print(f"Score: {score}")
print(f"Classification: {classification}")