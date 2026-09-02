import re
from typing import Optional, Dict, List, Union, Tuple
from datetime import datetime, timezone


def get_input() -> str:
    filepath = input("Enter the path to the .eml file: ").strip()
    return filepath


def read_eml_file(filepath: str) -> Optional[str]:
    if not filepath.lower().endswith(".eml"):
        print("⚠️ Warning: File doesn't have .eml extension")

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
        print("❌ Error: Could not decode file. Trying different encoding...")

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

    match = re.search(r"\r?\n\r?\n", content)

    if match:
        header = content[:match.start()]
        body = content[match.end():]
    else:
        header = content
        body = ""

    header_lines = header.splitlines()
    body_lines = body.splitlines()

    return header, body, len(header_lines), len(body_lines)


def print_first_headers(header: str, count: int = 5) -> None:
    lines = header.splitlines()
    actual_count = min(count, len(lines))

    print(f"\n📋 First {actual_count} Headers:")

    for i, line in enumerate(lines[:count], 1):
        display_line = line[:100] + "..." if len(line) > 100 else line
        print(f"{i}. {display_line}")

    if len(lines) > count:
        print(f"... and {len(lines) - count} more headers")


def is_folded_line(line: str) -> bool:
    return line.startswith((" ", "\t"))


def clean_header_key(key: str) -> str:
    key = key.rstrip(":")
    return key.lower().strip()


def clean_header_value(value: str) -> str:
    return " ".join(value.split())


def parse_headers(header_string: str) -> Dict[str, Union[str, List[str]]]:
    if not header_string:
        return {}

    headers: Dict[str, Union[str, List[str]]] = {}
    header_lines = header_string.splitlines()

    current_key: Optional[str] = None
    current_value: List[str] = []

    header_pattern = re.compile(r"^[!-9;-~]+:")

    def store_current_header() -> None:
        nonlocal current_key, current_value

        if current_key is None:
            return

        clean_key = clean_header_key(current_key)
        clean_val = clean_header_value(" ".join(current_value))

        if clean_key == "received":
            if clean_key not in headers:
                headers[clean_key] = [clean_val]
            else:
                existing = headers[clean_key]

                if isinstance(existing, list):
                    existing.append(clean_val)
                else:
                    headers[clean_key] = [existing, clean_val]

        elif clean_key in headers:
            existing = headers[clean_key]

            if isinstance(existing, list):
                existing.append(clean_val)
            else:
                headers[clean_key] = [existing, clean_val]

        else:
            headers[clean_key] = clean_val

        current_key = None
        current_value = []

    for line in header_lines:
        if not line.strip():
            continue

        candidate = line.lstrip(" \t")

        if header_pattern.match(candidate):
            store_current_header()

            key, value = candidate.split(":", 1)
            current_key = key.strip()
            current_value = [value.strip()]

        else:
            if current_key is not None:
                current_value.append(line.strip())

    store_current_header()

    return headers


def extract_email_domain(email: str) -> Optional[str]:
    if not email:
        return None

    email_match = re.search(
        r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
        email
    )

    if email_match:
        email_address = email_match.group(0)
        parts = email_address.split("@")

        if len(parts) == 2:
            return parts[1].lower()

    return None


def check_from_vs_return_path(headers: Dict) -> Dict:
    from_header = headers.get("from", "")
    return_path = headers.get("return-path", "")

    from_domain = extract_email_domain(from_header)
    return_domain = extract_email_domain(return_path)

    if not from_domain or not return_domain:
        return {
            "flag": False,
            "severity": "low",
            "details": "Could not extract domains for comparison"
        }

    if from_domain != return_domain:
        return {
            "flag": True,
            "severity": "high",
            "details": (
                f"From domain ({from_domain}) does not match "
                f"Return-Path ({return_domain})"
            )
        }

    return {
        "flag": False,
        "severity": "none",
        "details": f"Domains match: {from_domain}"
    }


def check_spf_dkim(headers: Dict) -> Dict:
    auth_results = headers.get("authentication-results", "")

    if isinstance(auth_results, list):
        auth_results = " ".join(auth_results)

    if not auth_results:
        return {
            "flag": True,
            "severity": "medium",
            "details": {
                "spf": "missing",
                "dkim": "missing",
                "message": "No authentication results found"
            }
        }

    spf_result = None
    dkim_result = None

    spf_match = re.search(r"spf=(\w+)", auth_results, re.IGNORECASE)

    if spf_match:
        spf_result = spf_match.group(1).lower()

    dkim_match = re.search(r"dkim=(\w+)", auth_results, re.IGNORECASE)

    if dkim_match:
        dkim_result = dkim_match.group(1).lower()

    flags = []
    severity = "low"

    if spf_result and spf_result != "pass":
        flags.append(f"SPF {spf_result}")
        severity = "high" if spf_result == "fail" else "medium"

    if dkim_result and dkim_result != "pass":
        flags.append(f"DKIM {dkim_result}")
        severity = "high" if dkim_result == "fail" else "medium"

    if not spf_result and not dkim_result:
        flags.append("No SPF or DKIM results")
        severity = "medium"

    return {
        "flag": len(flags) > 0,
        "severity": severity,
        "details": {
            "spf": spf_result or "not found",
            "dkim": dkim_result or "not found",
            "issues": flags if flags else ["All authentication passed"]
        }
    }


def analyze_received_chain(headers: Dict) -> Dict:
    received_headers = headers.get("received", [])

    if not isinstance(received_headers, list):
        received_headers = [received_headers] if received_headers else []

    hop_count = len(received_headers)

    if hop_count == 0:
        return {
            "flag": True,
            "severity": "medium",
            "details": {
                "hops": 0,
                "message": "No Received headers found (unusual)"
            }
        }

    issues = []

    if hop_count > 5:
        issues.append(f"Unusual number of hops: {hop_count}")

    suspicious_domains = [
        "attacker",
        "hacker",
        "phishing",
        "spam",
        "bad",
        "fraud"
    ]

    for hop in received_headers:
        hop_lower = hop.lower()

        for suspicious in suspicious_domains:
            if suspicious in hop_lower:
                issues.append(
                    f"Suspicious domain pattern found: {suspicious}"
                )
                break

    for hop in received_headers:
        if "from" not in hop.lower() or "by" not in hop.lower():
            issues.append("Malformed Received header missing from/by")
            break

    return {
        "flag": len(issues) > 0,
        "severity": (
            "high"
            if hop_count > 5
            else "medium"
            if issues
            else "low"
        ),
        "details": {
            "hops": hop_count,
            "issues": issues if issues else ["Normal received chain"],
            "first_hop": received_headers[0] if received_headers else "None",
            "last_hop": received_headers[-1] if received_headers else "None"
        }
    }


def check_date_anomaly(headers: Dict) -> Dict:
    date_header = headers.get("date", "")

    if isinstance(date_header, list):
        date_header = date_header[0] if date_header else ""

    if not date_header:
        return {
            "flag": False,
            "severity": "low",
            "details": "No date header found"
        }

    try:
        date_clean = re.sub(r"\([^)]*\)", "", date_header).strip()

        date_formats = [
            "%a, %d %b %Y %H:%M:%S %z",
            "%a, %d %b %Y %H:%M:%S",
            "%d %b %Y %H:%M:%S %z",
            "%d %b %Y %H:%M:%S",
        ]

        email_date = None

        for fmt in date_formats:
            try:
                email_date = datetime.strptime(date_clean, fmt)
                break
            except ValueError:
                continue

        if not email_date:
            return {
                "flag": False,
                "severity": "low",
                "details": "Could not parse date format"
            }

        if email_date.tzinfo is not None:
            now = datetime.now(timezone.utc)
            email_date_comparable = email_date.astimezone(timezone.utc)
        else:
            now = datetime.now()
            email_date_comparable = email_date

        if email_date_comparable > now:
            return {
                "flag": True,
                "severity": "high",
                "details": (
                    "Date is in the future: "
                    f"{email_date.strftime('%Y-%m-%d %H:%M')}"
                )
            }

        days_diff = (now - email_date_comparable).days

        if days_diff > 30:
            return {
                "flag": True,
                "severity": "medium",
                "details": f"Email is {days_diff} days old"
            }

        return {
            "flag": False,
            "severity": "none",
            "details": (
                "Date is normal: "
                f"{email_date.strftime('%Y-%m-%d %H:%M')}"
            )
        }

    except Exception as e:
        return {
            "flag": False,
            "severity": "low",
            "details": f"Could not analyze date: {str(e)}"
        }


def analyze_headers(headers: Dict) -> Dict:
    findings = []

    severity_scores = {
        "low": 1,
        "medium": 2,
        "high": 3
    }

    max_severity = "low"
    total_score = 0

    result1 = check_from_vs_return_path(headers)

    if result1["flag"]:
        findings.append({
            "check": "From vs Return-Path Mismatch",
            "severity": result1["severity"],
            "details": result1["details"]
        })

        max_severity = max(
            max_severity,
            result1["severity"],
            key=lambda x: severity_scores.get(x, 0)
        )

        total_score += severity_scores.get(result1["severity"], 0)

    result2 = check_spf_dkim(headers)

    if result2["flag"]:
        findings.append({
            "check": "SPF/DKIM Authentication",
            "severity": result2["severity"],
            "details": result2["details"]
        })

        max_severity = max(
            max_severity,
            result2["severity"],
            key=lambda x: severity_scores.get(x, 0)
        )

        total_score += severity_scores.get(result2["severity"], 0)

    result3 = analyze_received_chain(headers)

    if result3["flag"]:
        findings.append({
            "check": "Received Chain Analysis",
            "severity": result3["severity"],
            "details": result3["details"]
        })

        max_severity = max(
            max_severity,
            result3["severity"],
            key=lambda x: severity_scores.get(x, 0)
        )

        total_score += severity_scores.get(result3["severity"], 0)

    result4 = check_date_anomaly(headers)

    if result4["flag"]:
        findings.append({
            "check": "Date Anomaly",
            "severity": result4["severity"],
            "details": result4["details"]
        })

        max_severity = max(
            max_severity,
            result4["severity"],
            key=lambda x: severity_scores.get(x, 0)
        )

        total_score += severity_scores.get(result4["severity"], 0)

    critical_headers = [
        "from",
        "to",
        "subject",
        "date"
    ]

    missing = [
        h for h in critical_headers
        if h not in headers
    ]

    if missing:
        findings.append({
            "check": "Missing Critical Headers",
            "severity": "medium",
            "details": f"Missing: {', '.join(missing)}"
        })

        total_score += severity_scores["medium"]

        if max_severity == "low":
            max_severity = "medium"

    if total_score >= 5:
        overall_risk = "high"
    elif total_score >= 3:
        overall_risk = "medium"
    elif total_score >= 1:
        overall_risk = "low"
    else:
        overall_risk = "none"

    return {
        "summary": {
            "total_findings": len(findings),
            "max_severity": max_severity,
            "overall_risk": overall_risk,
            "risk_score": total_score
        },
        "findings": findings,
        "headers_analyzed": list(headers.keys())
    }


def generate_report(
    filepath: str,
    content: str,
    headers: Dict,
    analysis: Dict,
    header_lines: int,
    body_lines: int
) -> None:
    print("\n" + "=" * 70)
    print("📧 EMAIL HEADER ANALYZER - COMPLETE ANALYSIS REPORT")
    print("=" * 70)

    print("\n📁 FILE INFORMATION")
    print("-" * 70)
    print(f"File: {filepath}")
    print(f"Size: {len(content)} bytes")
    print(f"Total Lines: {len(content.splitlines())}")
    print(f"Header Lines: {header_lines}")
    print(f"Body Lines: {body_lines}")

    print("\n📋 HEADER SUMMARY")
    print("-" * 70)
    print(f"Total Unique Headers: {len(headers)}")

    print("\n🔒 SECURITY ANALYSIS SUMMARY")
    print("-" * 70)

    summary = analysis["summary"]

    print(f"Total Findings: {summary['total_findings']}")
    print(f"Max Severity: {summary['max_severity'].upper()}")
    print(f"Overall Risk Level: {summary['overall_risk'].upper()}")
    print(f"Risk Score: {summary['risk_score']}")

    if analysis["findings"]:
        print("\n⚠️ DETAILED FINDINGS")
        print("-" * 70)

        for i, finding in enumerate(analysis["findings"], 1):
            severity_color = {
                "high": "🔴",
                "medium": "🟡",
                "low": "🟢"
            }.get(finding["severity"], "⚪")

            print(f"\n{i}. {finding['check']}")
            print(
                f"   Severity: {severity_color} "
                f"{finding['severity'].upper()}"
            )

            if isinstance(finding["details"], dict):
                for key, value in finding["details"].items():
                    if isinstance(value, list):
                        print(f"   {key.capitalize()}:")

                        for item in value:
                            print(f"     - {item}")
                    else:
                        print(f"   {key.capitalize()}: {value}")
            else:
                print(f"   Details: {finding['details']}")

    else:
        print("\n✅ No security issues found!")

    print("\n💡 RECOMMENDED ACTIONS")
    print("-" * 70)

    if summary["overall_risk"] == "high":
        print("🔴 HIGH RISK - Immediate action required:")
        print("   • Do NOT click any links or download attachments")
        print("   • Do NOT reply to the email")
        print("   • Report to your security team")
        print("   • Delete the email after reporting")

    elif summary["overall_risk"] == "medium":
        print("🟡 MEDIUM RISK - Exercise caution:")
        print("   • Be cautious when interacting with this email")
        print("   • Verify sender identity through other channels")
        print("   • Check for suspicious links before clicking")

    elif summary["overall_risk"] == "low":
        print("🟢 LOW RISK - Minor concerns:")
        print("   • Review the specific findings above")
        print("   • Consider if this aligns with expected behavior")

    else:
        print("✅ NO RISK - Email appears legitimate")
        print("   • No security concerns detected")
        print("   • Follow normal email safety practices")

    print("\n📊 HEADERS ANALYZED")
    print("-" * 70)
    print(", ".join(sorted(analysis["headers_analyzed"])))

    print("\n" + "=" * 70)
    print("📧 Analysis Complete!")
    print("=" * 70 + "\n")