from detector.html_analyzer import analyze_html

url = "https://example.com"

result = analyze_html(url)

for r in result:
    print("[!]", r)