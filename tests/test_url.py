from detector.typosquat_detector import detect_typosquatting


def test_detect_typosquatting_returns_dict():
    url = "http://paypaI.com"
    result = detect_typosquatting(url)
    assert isinstance(result, dict)
    assert "suspicious" in result
    assert "indicators" in result