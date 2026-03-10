import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse

def get_html(url):
    
    try:
        response = requests.get(url,timeout = 10)
        if response.status_code == 200:
            return response.text
    except requests.RequestException as e:
        print(f"Error fetching URL: {e}")
    return None
def check_forms(soup):
    indicators = []
    forms = soup.find_all('form')
    for form in forms:
        inputs = form.find_all('input')
        for i in inputs:
            if i.get("type") == "password":
                indicators.append("Form with password field found")
    return indicators
def check_external_formn_action(soup, domain):
    indicators = []
    forms = soup.find_all('form')
    
    for form in forms:
        action = form.get('action')
        
        if action:
            parsed = urlparse(action)
            if parsed.netloc and parsed.netloc != domain:
                indicators.append(f"Form action points to external domain: {parsed.netloc}")
    return indicators

def check_iframes(soup):
    indicators = []

    iframes = soup.find_all('iframe')

    if len(iframes) > 0:
        indicators.append(f"{len(iframes)} iframe(s) found")
    return indicators
def check_suspicious_keywords(html):
    indicators = []
    suspicious_keywords = ['login', 
                'secure', 
                'account', 
                'update', 
                'free', 
                'verify', 
                'password',
                'bank', 
                'confirm', 
                'security']
    html_lower = html.lower()
    
    for keyword in suspicious_keywords:
        if keyword in html_lower:
            indicators.append(f"Suspicious keyword found: {keyword}")
    return indicators


