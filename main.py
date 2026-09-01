from email_analyzer import (
    get_input,
    read_eml_file,
    split_headers_body,
    print_first_headers
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

    print("\n✅ Email analysis complete!")

if __name__ == "__main__":
    main()