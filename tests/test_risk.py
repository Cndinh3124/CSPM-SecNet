from python.secnet_cspm.risk import risk_score, risk_level

def test_high():
    assert risk_score("HIGH") >= 70
    assert risk_level(80) == "HIGH"

def test_low():
    assert risk_level(25) == "LOW"
