import unittest

from phishing_detector.url_heuristics import (
    assess_url,
    check_at_symbol,
    check_excessive_subdomains,
    check_ip_hostname,
    check_suspicious_tld,
    check_typosquat,
    check_url_shortener,
)


class TestIndividualUrlHeuristics(unittest.TestCase):
    def test_ip_hostname_detected(self):
        signal = check_ip_hostname("192.168.0.1")
        self.assertTrue(signal.fired)

    def test_ip_hostname_not_flagged_for_domain(self):
        signal = check_ip_hostname("example.com")
        self.assertFalse(signal.fired)

    def test_excessive_subdomains_detected(self):
        signal = check_excessive_subdomains("a.b.c.paypal.com")
        self.assertTrue(signal.fired)

    def test_excessive_subdomains_not_flagged_for_normal_host(self):
        signal = check_excessive_subdomains("www.paypal.com")
        self.assertFalse(signal.fired)

    def test_at_symbol_detected(self):
        signal = check_at_symbol("http://www.paypal.com@192.168.1.1/login")
        self.assertTrue(signal.fired)

    def test_at_symbol_not_flagged_for_normal_url(self):
        signal = check_at_symbol("http://example.com/login")
        self.assertFalse(signal.fired)

    def test_suspicious_tld_detected(self):
        signal = check_suspicious_tld("free-rewards-claim.tk")
        self.assertTrue(signal.fired)

    def test_suspicious_tld_not_flagged_for_dot_com(self):
        signal = check_suspicious_tld("example.com")
        self.assertFalse(signal.fired)

    def test_typosquat_detected_against_bundled_domain_list(self):
        signal, closest = check_typosquat("paypa1.com")
        self.assertTrue(signal.fired)
        self.assertEqual(closest, "paypal.com")

    def test_typosquat_not_flagged_for_clearly_legit_domain(self):
        signal, closest = check_typosquat("google.com")
        self.assertFalse(signal.fired)
        self.assertIsNone(closest)

    def test_url_shortener_detected(self):
        signal = check_url_shortener("bit.ly")
        self.assertTrue(signal.fired)

    def test_url_shortener_not_flagged_for_normal_host(self):
        signal = check_url_shortener("example.com")
        self.assertFalse(signal.fired)


class TestCombinedRiskScoring(unittest.TestCase):
    def test_clean_benign_url_is_low_risk(self):
        assessment = assess_url("https://www.wikipedia.org/wiki/Python")
        self.assertEqual(assessment.verdict, "low")
        self.assertEqual(len(assessment.fired_signals()), 0, msg=[s.name for s in assessment.fired_signals()])

    def test_two_moderate_signals_escalate_to_medium(self):
        # suspicious TLD (.xyz) + suspicious keyword ("account") in the path.
        assessment = assess_url("http://secure-login.xyz/account")
        fired_names = {s.name for s in assessment.fired_signals()}
        self.assertIn("suspicious_tld", fired_names)
        self.assertIn("suspicious_keywords", fired_names)
        self.assertEqual(assessment.verdict, "medium")

    def test_multiple_strong_signals_escalate_to_high(self):
        # '@' obfuscation + IP-address host + a sensitive keyword in the path.
        assessment = assess_url("http://paypal.com@192.168.1.1/verify")
        fired_names = {s.name for s in assessment.fired_signals()}
        self.assertIn("at_symbol", fired_names)
        self.assertIn("ip_hostname", fired_names)
        self.assertIn("suspicious_keywords", fired_names)
        self.assertEqual(assessment.verdict, "high")

    def test_verdict_escalates_monotonically_with_more_signals(self):
        low = assess_url("https://www.wikipedia.org/wiki/Python")
        medium = assess_url("http://secure-login.xyz/account")
        high = assess_url("http://paypal.com@192.168.1.1/verify")
        self.assertLess(low.score, medium.score)
        self.assertLess(medium.score, high.score)


if __name__ == "__main__":
    unittest.main()
