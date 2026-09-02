from email_analyzer import parse_headers, split_headers_body

def test_parse():
    test_email = """From: test@example.com
To: recipient@example.com
Subject: Test Email
Received: from server1.com
Received: from server2.com

Body here"""
    
    header, body, h, b = split_headers_body(test_email)
    headers = parse_headers(header)
    
    print("Headers parsed:")
    for key, value in headers.items():
        print(f"  {key}: {value}")
    
    print(f"\nFrom: {headers.get('from')}")
    print(f"Subject: {headers.get('subject')}")
    print(f"Received count: {len(headers.get('received', []))}")

if __name__ == "__main__":
    test_parse()