import unittest
import sys
import os

sys.path.insert(
    0,
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)

from email_analyzer import (
    read_eml_file,
    split_headers_body,
    parse_headers,
    is_folded_line,
    clean_header_key,
    clean_header_value,
    extract_email_domain,
    check_from_vs_return_path,
    check_spf_dkim,
    analyze_received_chain,
    analyze_headers,
    analyze_display_name,
    analyze_subject,
    analyze_urls,
    check_reply_to_spoofing    
)

class TestPhase1(unittest.TestCase):
    def test_clean_header_key(self):
        self.assertEqual(clean_header_key("From"), "from")
        self.assertEqual(clean_header_key("  Subject  "), "subject")
        self.assertEqual(
            clean_header_key("RETURN-PATH"),
            "return-path"
        )

    def test_clean_header_value(self):
        self.assertEqual(
            clean_header_value("  test@example.com  "),
            "test@example.com"
        )

        self.assertEqual(
            clean_header_value(
                "line1\n  line2\n    line3"
            ),
            "line1 line2 line3"
        )

    def test_is_folded_line(self):
        self.assertTrue(is_folded_line("  continued line"))
        self.assertTrue(is_folded_line("\tcontinued line"))
        self.assertFalse(
            is_folded_line("New header: value")
        )

class TestPhase2(unittest.TestCase):
    def test_parse_headers_simple(self):
        header_string = """From: test@example.com
        To: recipient@example.com
        Subject: Simple Test"""

        headers = parse_headers(header_string)

        self.assertEqual(
            headers.get("from"),
            "test@example.com"
        )

        self.assertEqual(
            headers.get("to"),
            "recipient@example.com"
        )

        self.assertEqual(
            headers.get("subject"),
            "Simple Test"
        )

    def test_parse_headers_folded(self):
        header_string = """Subject: This is a very long
        subject that continues
        on multiple lines
        From: test@example.com"""

        headers = parse_headers(header_string)

        self.assertEqual(
            headers.get("subject"),
            "This is a very long subject that continues on multiple lines"
        )

        self.assertEqual(
            headers.get("from"),
            "test@example.com"
        )

    def test_parse_headers_duplicates(self):
        header_string = """Received: from server1.com
        Received: from server2.com
        Received: from server3.com
        From: test@example.com"""

        headers = parse_headers(header_string)

        self.assertIsInstance(
            headers.get("received"),
            list
        )

        self.assertEqual(
            len(headers.get("received", [])),
            3
        )

    def test_parse_headers_mixed_case(self):
        header_string = """FROM: test@example.com
        to: recipient@example.com
        Subject: Test"""

        headers = parse_headers(header_string)

        self.assertEqual(
            headers.get("from"),
            "test@example.com"
        )

        self.assertEqual(
            headers.get("to"),
            "recipient@example.com"
        )

        self.assertEqual(
            headers.get("subject"),
            "Test"
        )

class TestPhase3(unittest.TestCase):
    def test_extract_email_domain(self):
        self.assertEqual(
            extract_email_domain("user@domain.com"),
            "domain.com"
        )

        self.assertEqual(
            extract_email_domain(
                '"Name" <user@domain.com>'
            ),
            "domain.com"
        )

        self.assertEqual(
            extract_email_domain(
                "<user@domain.com>"
            ),
            "domain.com"
        )

        self.assertIsNone(
            extract_email_domain("invalid")
        )

    def test_check_from_vs_return_path(self):
        headers = {
            "from": "user@domain.com",
            "return-path": "<user@domain.com>"
        }

        result = check_from_vs_return_path(headers)

        self.assertFalse(result["flag"])

        headers = {
            "from": "user@domain.com",
            "return-path": "<user@phishing.com>"
        }

        result = check_from_vs_return_path(headers)

        self.assertTrue(result["flag"])

        self.assertEqual(
            result["severity"],
            "high"
        )

    def test_check_spf_dkim(self):
        headers = {
            "authentication-results": "spf=pass; dkim=pass"
        }

        result = check_spf_dkim(headers)

        self.assertFalse(result["flag"])

        headers = {
            "authentication-results": "spf=fail; dkim=neutral"
        }

        result = check_spf_dkim(headers)

        self.assertTrue(result["flag"])

        self.assertIn(
            result["severity"],
            ["high", "medium"]
        )

    def test_analyze_received_chain(self):
        headers = {
            "received": [
                "from mail1.com by mail2.com",
                "from mail2.com by mail3.com"
            ]
        }

        result = analyze_received_chain(headers)

        self.assertFalse(result["flag"])

        headers = {
            "received": [
                "from mail1.com by mail2.com",
                "from mail2.com by mail3.com",
                "from mail3.com by mail4.com",
                "from mail4.com by mail5.com",
                "from mail5.com by mail6.com",
                "from mail6.com by mail7.com"
            ]
        }

        result = analyze_received_chain(headers)

        self.assertTrue(result["flag"])

        self.assertEqual(
            result["severity"],
            "high"
        )

    def test_analyze_headers_comprehensive(self):
        headers = {
            "from": "user@domain.com",
            "return-path": "<user@phishing.com>",
            "to": "recipient@example.com",
            "subject": "Test",
            "date": "Mon, 1 Jan 2026 10:00:00 +0000",
            "received": [
                "from mail1.com by mail2.com"
            ],
            "authentication-results": "spf=fail; dkim=neutral"
        }

        analysis = analyze_headers(headers)

        self.assertGreaterEqual(
            analysis["summary"]["total_findings"],
            1
        )

        self.assertIn(
            "overall_risk",
            analysis["summary"]
        )

        self.assertIsInstance(
            analysis["findings"],
            list
        )

class TestIntegration(unittest.TestCase):
    def test_full_pipeline(self):
        test_email = """From: test@example.com
        To: recipient@example.com
        Subject: Test Email
        Return-Path: <test@example.com>
        Received: from server1.com
        by server2.com
        Authentication-Results: spf=pass; dkim=pass
        Date: Mon, 1 Jan 2026 10:00:00 +0000

        This is the body of the test email.
        It has multiple lines.
        """

        header, body, h_count, b_count = split_headers_body(
            test_email
        )

        headers = parse_headers(header)
        analysis = analyze_headers(headers)

        self.assertEqual(
            headers.get("from"),
            "test@example.com"
        )

        self.assertEqual(
            headers.get("to"),
            "recipient@example.com"
        )

        self.assertEqual(
            headers.get("subject"),
            "Test Email"
        )

        self.assertEqual(
            headers.get("return-path"),
            "<test@example.com>"
        )

        self.assertIsInstance(
            headers.get("received"),
            list
        )

        self.assertEqual(
            len(headers.get("received", [])),
            1
        )
class TestDay1Features(unittest.TestCase):
    def test_analyze_urls_normal(self):
        body = "Check this link: https://example.com"
        result = analyze_urls(body)
        self.assertEqual(result['url_count'], 1)
        self.assertEqual(len(result['suspicious_urls']), 0)
        self.assertEqual(len(result['shortened_urls']), 0)
    
    def test_analyze_urls_suspicious(self):
        body = "Verify here: http://bit.ly/verify-account"
        result = analyze_urls(body)
        self.assertEqual(result['url_count'], 1)
        self.assertEqual(len(result['suspicious_urls']), 1)
        self.assertEqual(len(result['shortened_urls']), 1)
    
    def test_analyze_urls_ip(self):
        body = "Click: http://192.168.1.1/phishing"
        result = analyze_urls(body)
        self.assertEqual(result['url_count'], 1)
        self.assertEqual(len(result['suspicious_urls']), 1)
        self.assertEqual(len(result['ip_urls']), 1)
    
    def test_analyze_subject_normal(self):
        subject = "Your order #12345 confirmation"
        result = analyze_subject(subject)
        self.assertFalse(result['is_suspicious'])
        self.assertEqual(result['keyword_count'], 0)
    
    def test_analyze_subject_urgent(self):
        subject = "URGENT: Your account needs immediate attention"
        result = analyze_subject(subject)
        self.assertTrue(result['is_suspicious'])
        self.assertIn('urgency', result['flags'])
    
    def test_analyze_subject_threat(self):
        subject = "Your account has been suspended - Action Required"
        result = analyze_subject(subject)
        self.assertTrue(result['is_suspicious'])
        self.assertIn('threat', result['flags'])
    
    def test_analyze_subject_financial(self):
        subject = "Important: Verify your bank account information"
        result = analyze_subject(subject)
        self.assertTrue(result['is_suspicious'])
        self.assertIn('financial', result['flags'])
    
    def test_check_reply_to_spoofing_legitimate(self):
        headers = {
            'from': 'user@example.com',
            'reply-to': 'user@example.com'
        }
        result = check_reply_to_spoofing(headers)
        self.assertFalse(result['flag'])
    
    def test_check_reply_to_spoofing_suspicious(self):
        headers = {
            'from': 'support@amazon.com',
            'reply-to': 'hacker@gmail.com'
        }
        result = check_reply_to_spoofing(headers)
        self.assertTrue(result['flag'])
        self.assertEqual(result['severity'], 'high')
    
    def test_check_reply_to_spoofing_no_header(self):
        headers = {
            'from': 'user@example.com'
        }
        result = check_reply_to_spoofing(headers)
        self.assertFalse(result['flag'])
    
    def test_analyze_display_name_legitimate(self):
        headers = {
            'from': 'John Doe <john@company.com>'
        }
        result = analyze_display_name(headers)
        self.assertFalse(result['flag'])
    
    def test_analyze_display_name_suspicious(self):
        headers = {
            'from': '"PayPal Support" <scammer@gmail.com>'
        }
        result = analyze_display_name(headers)
        self.assertTrue(result['flag'])
        self.assertEqual(result['severity'], 'high')
    
    def test_analyze_display_name_free_email(self):
        headers = {
            'from': '"Admin Team" <admin@gmail.com>'
        }
        result = analyze_display_name(headers)
        self.assertTrue(result['flag'])
    
    def test_analyze_display_name_no_display_name(self):
        headers = {
            'from': 'user@example.com'
        }
        result = analyze_display_name(headers)
        self.assertFalse(result['flag'])
class TestDay1Integration(unittest.TestCase):
    def test_full_pipeline_with_suspicious_email(self):
        test_email = """From: "PayPal Support" <scammer@gmail.com>
        Reply-To: hacker@gmail.com
        Subject: URGENT: Your Account Will Be Suspended
        Return-Path: <scammer@gmail.com>
        Date: Mon, 1 Jan 2026 10:00:00 +0000

        Dear Customer,

        Your PayPal account has been flagged for suspicious activity.
        Please verify your account immediately:
        http://bit.ly/verify-paypal-account

        Thank you,
        PayPal Team"""
        
        header, body, h, b = split_headers_body(test_email)
        headers = parse_headers(header)
        analysis = analyze_headers(headers, body)
        
        self.assertGreaterEqual(analysis['summary']['total_findings'], 3)
        self.assertEqual(analysis['summary']['overall_risk'], 'high')
        
        finding_names = [f['check'] for f in analysis['findings']]
        self.assertIn('Suspicious URLs Detected', finding_names)
        self.assertIn('Suspicious Subject Line', finding_names)
        self.assertIn('Reply-To Spoofing', finding_names)
        self.assertIn('Suspicious Display Name', finding_names)

if __name__ == "__main__":
    unittest.main()