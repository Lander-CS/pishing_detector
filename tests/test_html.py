from detector.html_analyzer import analyze_html


def test_analyze_html_returns_list():
    url = "https://example.com"
    result = analyze_html(url)
    assert isinstance(result, list)