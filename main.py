from email_analyzer import (
    get_input,
    read_eml_file,
    split_headers_body,
    print_first_headers,
    parse_headers
)

def main():
    print("\n" + "="*70)
    print("📧 EMAIL HEADER ANALYZER - Phishing Detection Tool")
    print("="*70 + "\n")
    filepath = get_input()
    if not filepath:
        print("❌ No file path provided!")
        return
    print("\n" + "="*70)
    print("📧 PHASE 1: File Reading & Splitting")
    print("="*70)
    content = read_eml_file(filepath)
    if content is None:
        print("❌ Cannot proceed without file content!")
        return
    header, body, header_lines, body_lines = split_headers_body(content)
    print(f"\n✅ File read successfully ({len(content)} bytes)")
    print(f"\n📊 File Statistics:")
    print(f"  - Total lines: {len(content.splitlines())}")
    print(f"  - Header lines: {header_lines}")
    print(f"  - Body lines: {body_lines}")
    print_first_headers(header)
    body_preview = body.splitlines()[:3]
    if body_preview:
        print(f"\n📝 Body preview (first {len(body_preview)} lines):")
        for line in body_preview:
            display_line = line[:100] + "..." if len(line) > 100 else line
            print(f"  {display_line}")
    else:
        print("\n📝 No body content found")

    print("\n" + "="*70)
    print("📧 PHASE 2: Header Parsing")
    print("="*70)
    headers = parse_headers(header)
    print(f"\n📋 Parsed Headers ({len(headers)} unique headers):")
    important = ['from', 'to', 'subject', 'date', 'return-path', 
                 'authentication-results', 'message-id']
    print("\n📌 Important Headers:")
    for key in important:
        if key in headers:
            value = headers[key]
            if isinstance(value, list):
                print(f"  {key}: [{len(value)} entries]")
            else:
                display_value = value[:80] + "..." if len(value) > 80 else value
                print(f"  {key}: {display_value}")
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

    print("\n✅ Email analysis complete!")

if __name__ == "__main__":
    main()