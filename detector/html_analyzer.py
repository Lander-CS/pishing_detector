import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse

from .models import Indicator, IndicatorCategory, Severity

MAX_HTML_CHARS = 500_000


def get_html(url):

    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            # Limita o tamanho máximo para evitar consumo excessivo de memória
            return response.text[:MAX_HTML_CHARS]
    except requests.RequestException as e:
        print(f"Error fetching URL: {e}")
    return None


def check_forms(soup):
    indicators: list[Indicator] = []
    forms = soup.find_all('form')
    for form in forms:
        inputs = form.find_all('input')
        for i in inputs:
            if i.get("type") == "password":
                indicators.append(
                    Indicator(
                        category=IndicatorCategory.HTML_ISSUE,
                        message="Form with password field found",
                        severity=Severity.HIGH,
                    )
                )
    return indicators


def check_external_form_action(soup, domain):
    indicators: list[Indicator] = []
    forms = soup.find_all('form')
    
    for form in forms:
        action = form.get('action')
        
        if action:
            parsed = urlparse(action)
            if parsed.netloc and parsed.netloc != domain:
                indicators.append(
                    Indicator(
                        category=IndicatorCategory.HTML_ISSUE,
                        message=f"Form action points to external domain: {parsed.netloc}",
                        severity=Severity.MEDIUM,
                    )
                )
    return indicators


def check_iframes(soup):
    indicators: list[Indicator] = []

    iframes = soup.find_all('iframe')

    if len(iframes) > 0:
        indicators.append(
            Indicator(
                category=IndicatorCategory.HTML_ISSUE,
                message=f"{len(iframes)} iframe(s) found",
                severity=Severity.MEDIUM,
            )
        )
    return indicators


def check_suspicious_keywords(html):
    indicators: list[Indicator] = []
    suspicious_keywords = [
        "login",
        "secure",
        "account",
        "update",
        "free",
        "verify",
        "password",
        "bank",
        "confirm",
        "security",
    ]
    html_lower = html.lower()
    
    for keyword in suspicious_keywords:
        if keyword in html_lower:
            indicators.append(
                Indicator(
                    category=IndicatorCategory.HTML_ISSUE,
                    message=f"Suspicious keyword found: {keyword}",
                    severity=Severity.MEDIUM,
                )
            )
    return indicators


def analyze_html_indicators(url):
    indicators: list[Indicator] = []
    html = get_html(url)
    if not html:
        indicators.append(
            Indicator(
                category=IndicatorCategory.HTML_ISSUE,
                message="Failed to retrieve HTML content",
                severity=Severity.MEDIUM,
            )
        )
        return indicators
    soup = BeautifulSoup(html, 'html.parser')
    domain = urlparse(url).netloc
    indicators.extend(check_forms(soup))
    indicators.extend(check_external_form_action(soup, domain))
    indicators.extend(check_iframes(soup))
    indicators.extend(check_suspicious_keywords(html))
    return indicators


def analyze_html(url):
    """
    Backwards-compatible wrapper returning only indicator messages.

    Prefer usar analyze_html_indicators para obter objetos estruturados.
    """
    return [indicator.message for indicator in analyze_html_indicators(url)]
