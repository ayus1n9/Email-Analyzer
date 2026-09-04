"""
Email Header Analyzer - Main Execution Script
Complete implementation with all phases + Day 1 features
"""

from email_analyzer import (
    get_input,
    read_eml_file,
    split_headers_body,
    print_first_headers,
    parse_headers,
    analyze_headers,
    generate_report
)

def main():
    """
    Main execution flow:
    Phase 1: Read and split email
    Phase 2: Parse headers
    Phase 3: Security analysis (with Day 1 features)
    Phase 4: Generate report
    """
    print("\n" + "="*70)
    print("📧 EMAIL HEADER ANALYZER - Phishing Detection Tool")
    print("="*70 + "\n")
    
    # Get input
    filepath = get_input()
    if not filepath:
        print("❌ No file path provided!")
        return
    
    print("\n" + "="*70)
    print("📧 PHASE 1: File Reading & Splitting")
    print("="*70)
    
    # Read file
    content = read_eml_file(filepath)
    if content is None:
        print("❌ Cannot proceed without file content!")
        return
    
    # Split headers and body
    header, body, header_lines, body_lines = split_headers_body(content)
    
    # Display Phase 1 results
    print(f"\n✅ File read successfully ({len(content)} bytes)")
    print(f"\n📊 File Statistics:")
    print(f"  - Total lines: {len(content.splitlines())}")
    print(f"  - Header lines: {header_lines}")
    print(f"  - Body lines: {body_lines}")
    
    print_first_headers(header)
    
    # Preview body
    body_preview = body.splitlines()[:3]
    if body_preview:
        print(f"\n📝 Body preview (first {len(body_preview)} lines):")
        for line in body_preview:
            display_line = line[:100] + "..." if len(line) > 100 else line
            print(f"  {display_line}")
    else:
        print("\n📝 No body content found")
    
    # Phase 2: Parse headers
    print("\n" + "="*70)
    print("📧 PHASE 2: Header Parsing")
    print("="*70)
    
    headers = parse_headers(header)
    
    print(f"\n📋 Parsed Headers ({len(headers)} unique headers):")
    
    # Display important headers
    important = ['from', 'to', 'subject', 'date', 'return-path', 
                 'authentication-results', 'message-id', 'reply-to']
    
    print("\n📌 Important Headers:")
    for key in important:
        if key in headers:
            value = headers[key]
            if isinstance(value, list):
                print(f"  {key}: [{len(value)} entries]")
            else:
                display_value = value[:80] + "..." if len(value) > 80 else value
                print(f"  {key}: {display_value}")
    
    # Display all other headers
    other_headers = [k for k in headers.keys() if k not in important]
    if other_headers:
        print(f"\n📌 Other Headers ({len(other_headers)}):")
        for key in sorted(other_headers):
            value = headers[key]
            if isinstance(value, list):
                print(f"  {key}: [{len(value)} entries]")
            else:
                display_value = value[:60] + "..." if len(value) > 60 else value
                print(f"  {key}: {display_value}")
    
    # Phase 3: Security Analysis (with Day 1 features)
    print("\n" + "="*70)
    print("📧 PHASE 3: Security Analysis (with Advanced Features)")
    print("="*70)
    
    # Pass body for URL analysis
    analysis = analyze_headers(headers, body)
    
    # Display analysis summary
    summary = analysis['summary']
    print(f"\n🔒 Analysis Summary:")
    print(f"  - Total Findings: {summary['total_findings']}")
    print(f"  - Max Severity: {summary['max_severity'].upper()}")
    print(f"  - Overall Risk Level: {summary['overall_risk'].upper()}")
    print(f"  - Risk Score: {summary['risk_score']}/10")
    
    # Display findings with categorized sections
    if analysis['findings']:
        print(f"\n⚠️ Security Findings:")
        for i, finding in enumerate(analysis['findings'], 1):
            severity_icon = {
                'high': '🔴',
                'medium': '🟡',
                'low': '🟢'
            }.get(finding['severity'], '⚪')
            
            print(f"\n  {i}. {finding['check']}")
            print(f"     {severity_icon} Severity: {finding['severity'].upper()}")
            
            if isinstance(finding['details'], dict):
                for key, value in finding['details'].items():
                    if isinstance(value, list):
                        print(f"     {key.capitalize().replace('_', ' ')}:")
                        for item in value:
                            print(f"       - {item}")
                    else:
                        formatted_key = key.capitalize().replace('_', ' ')
                        print(f"     {formatted_key}: {value}")
            else:
                print(f"     Details: {finding['details']}")
    else:
        print(f"\n✅ No security issues detected!")
    
    # Phase 4: Generate Report
    print("\n" + "="*70)
    print("📧 PHASE 4: Complete Report")
    print("="*70)
    
    generate_report(filepath, content, headers, analysis, header_lines, body_lines)
    
    print("\n✅ Email analysis complete!")

if __name__ == "__main__":
    main()