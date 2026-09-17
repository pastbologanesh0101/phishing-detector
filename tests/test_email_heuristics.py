import unittest

from phishing_detector.email_heuristics import (
    assess_email_text,
    check_generic_greeting,
    check_mismatched_links,
    check_sensitive_info_request,
    check_urgency_language,
)


class TestIndividualEmailHeuristics(unittest.TestCase):
    def test_urgency_language_detected(self):
        text = "Your account has been suspended. Act now to restore access."
        signal = check_urgency_language(text)
        self.assertTrue(signal.fired)

    def test_urgency_language_not_flagged_for_normal_text(self):
        text = "Thanks for signing up for our newsletter, here is this week's roundup."
        signal = check_urgency_language(text)
        self.assertFalse(signal.fired)

    def test_mismatched_display_link_detected(self):
        text = '<a href="http://evil-phish.ru/login">http://www.paypal.com/login</a>'
        signal = check_mismatched_links(text)
        self.assertTrue(signal.fired)

    def test_mismatched_display_link_not_flagged_when_consistent(self):
        text = '<a href="http://www.paypal.com/login">http://www.paypal.com/login</a>'
        signal = check_mismatched_links(text)
        self.assertFalse(signal.fired)

    def test_generic_greeting_detected(self):
        text = "Dear Customer,\n\nWe noticed a new sign-in to your account."
        signal = check_generic_greeting(text)
        self.assertTrue(signal.fired)

    def test_generic_greeting_not_flagged_for_personalized_name(self):
        text = "Hi Priya,\n\nThanks for reaching out last week."
        signal = check_generic_greeting(text)
        self.assertFalse(signal.fired)

    def test_sensitive_info_request_detected(self):
        text = "Please enter your password and social security number to verify your account."
        signal = check_sensitive_info_request(text)
        self.assertTrue(signal.fired)

    def test_sensitive_info_request_not_flagged_for_normal_text(self):
        text = "Please read the attached newsletter for this month's highlights."
        signal = check_sensitive_info_request(text)
        self.assertFalse(signal.fired)


class TestCombinedEmailRiskScoring(unittest.TestCase):
    def test_clean_benign_email_is_low_risk(self):
        text = (
            "Hi Priya,\n\n"
            "Thanks for signing up for our newsletter. Here's this week's "
            "roundup of articles you might enjoy.\n\n"
            "Best,\nThe Editorial Team"
        )
        assessment = assess_email_text(text)
        self.assertEqual(assessment.verdict, "low")
        self.assertEqual(len(assessment.fired_signals()), 0, msg=[s.name for s in assessment.fired_signals()])

    def test_multi_signal_phishing_email_is_high_risk(self):
        text = (
            "Dear Customer,\n\n"
            "Your account has been suspended due to unusual activity detected. "
            "Act now and verify your account immediately by entering your "
            "password and social security number below.\n\n"
            '<a href="http://evil-phish.ru/login">http://www.paypal.com/login</a>'
        )
        assessment = assess_email_text(text)
        fired_names = {s.name for s in assessment.fired_signals()}
        self.assertIn("urgency_language", fired_names)
        self.assertIn("generic_greeting", fired_names)
        self.assertIn("sensitive_info_request", fired_names)
        self.assertIn("mismatched_link", fired_names)
        self.assertEqual(assessment.verdict, "high")


if __name__ == "__main__":
    unittest.main()
