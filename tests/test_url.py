from detector.typosquat_detector import detect_typosquatting

url = "http://paypaI.com"

result = detect_typosquatting(url)

for r in result:
    print("[!]", r)