from detector.domain_analyzer import extract_domain

def test_extract_domain():

    url = "https://login.paypal.com/account"

    domain = extract_domain(url)

    assert domain == "login.paypal.com"