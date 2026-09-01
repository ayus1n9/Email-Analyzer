import re
from typing import Optional, Dict, List, Union, Tuple
from datetime import datetime
from collections import Counter

def get_input() -> str:
    filepath = input("Enter the path to the .eml file: ").strip()
    return filepath

def read_eml_file(filepath: str) -> Optional[str]:
    if not filepath.lower().endswith(".eml"):
        print(f"⚠️ Warning: File doesn't have .eml extension")
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read()
            if not content:
                print("⚠️ Warning: File is empty!")
            return content
    except FileNotFoundError:
        print(f"❌ Error: File not found at: {filepath}")
        return None
    except UnicodeDecodeError:
        print(f"❌ Error: Could not decode file. Trying different encoding...")
        try:
            with open(filepath, "r", encoding="latin-1") as f:
                return f.read()
        except Exception as e:
            print(f"❌ Error: Could not read with latin-1 encoding: {e}")
            return None
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        return None

def split_headers_body(content: str) -> Tuple[str, str, int, int]:
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

def print_first_headers(header: str, count: int = 5) -> None:
    """Print first N headers from header string."""
    lines = header.splitlines()
    actual_count = min(count, len(lines))
    print(f"\n📋 First {actual_count} Headers:")
    for i, line in enumerate(lines[:count], 1):
        display_line = line[:100] + "..." if len(line) > 100 else line
        print(f"{i}. {display_line}")
    if len(lines) > count:
        print(f"... and {len(lines) - count} more headers")