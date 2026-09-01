from email_analyzer import(
    get_input,
    read_eml_file,
    split_headers_body,
    print_first_headers
)

def main():
    filepath = get_input()
    content = read_eml_file(filepath)
    if content is None:
        print("❌ Cannot proceed without file content!")
        return
    header, body, header_lines, body_lines = split_headers_body(content)
    print("📧 EMAIL HEADER ANALYZER - PHASE 1")
    print(f"📁 File: {filepath}")
    print(f"\n✅ File read successfully ({len(content)} bytes)")
    print(f"\n📊 File Statistics:")
    print(f"- Total lines: {len(content.splitlines())}")
    print(f"- Header lines: {header_lines}")
    print(f"- Body lines: {body_lines}")
    print_first_headers(header)
    body_preview = body.splitlines()[:3]
    if body_preview:
        print(f"\n📝 Body preview (first {len(body_preview)} lines):")
        for line in body_preview:
            print(f"  {line[:100]}{'...' if len(line) > 100 else ''}")
    else:
        print("\n📝 No body content found")
    print(f"\n✅ Email analysis complete!")

if __name__ == "__main__":
    main()
