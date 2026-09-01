from typing import Optional, Tuple

def get_input() -> str:
    filepath=input("Enter the filepath:")
    return filepath

def read_eml_file(filepath) -> Optional[str]:
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read()
            if not filepath.lower().endswith(".eml"):
                print(f"⚠️ Warning: File doesn't have .eml extension")
            return content
    except FileNotFoundError:
        print(f"❌ Error: File not found at: {filepath}")
        return None
    except UnicodeDecodeError:
        print(f"❌ Error: Could not decode file. Trying different encoding...")
        with open(filepath, "r", encoding="latin-1") as f:
            return f.read()

def split_headers_body(content) -> Tuple[str, str, int, int]:
    if not content:
        return "", "", 0, 0
    parts = content.split("\n\n", 1)
    if len(parts) == 2:
        header, body = parts
    else:
        header = parts[0]
        body = ""
    header_lines = header.splitlines()
    body_lines = body.splitlines()
    return header, body, len(header_lines), len(body_lines)

def print_first_headers(header, count=5):
    lines = header.splitlines()
    print(f"\n📋 First {count} Headers:")
    for i, line in enumerate(lines[:count], 1):
        print(f"{i}. {line}")
    if len(lines) > count:
        print(f"... and {len(lines) - count} more headers")

