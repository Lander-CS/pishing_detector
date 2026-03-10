# Phishing Detector
A phishing detection tool based on heuristic URL analysis.

## Features
- IP-based URL detection: Identifies if a URL uses a raw IP address instead of a domain name.
- Multiple subdomains: Detects an unusual number of subdomains.
- Suspicious keyword identification: Flags common phishing terms (e.g., "login", "verify", "secure").
- URL length analysis: Analyzes whether the URL is excessively long to hide its true destination.

## Usage Example
```
python main.py https://secure-login-paypal.com
```
## Output
Risk Score: 4

Indicators:

[!] Suspicious keyword

[!] Long URL

## Technologies Used
-Python

-Regex (Regular Expressions)

-URL parsing