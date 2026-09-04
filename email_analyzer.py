import config as Config
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

def analyze_urls(body: str) -> Dict:
    if not body:
        return {
            'url_count': 0,
            'suspicious_urls': [],
            'shortened_urls': [],
            'all_urls': [],
            'ip_urls': []
        }
    
    url_pattern = r'https?://[^\s<>"\'{}|\\^`\[\]]+'
    urls = re.findall(url_pattern, body)
    
    if not urls:
        return {
            'url_count': 0,
            'suspicious_urls': [],
            'shortened_urls': [],
            'all_urls': [],
            'ip_urls': []
        }
    
    suspicious_urls = []
    shortened_urls = []
    ip_urls = []
    
    for url in urls:
        url_lower = url.lower()
        if any(shortener in url_lower for shortener in Config.URL_SHORTENERS):
            shortened_urls.append(url)
            suspicious_urls.append(url)
        if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url):
            ip_urls.append(url)
            suspicious_urls.append(url)
        if any(url_lower.endswith(tld) for tld in Config.SUSPICIOUS_TLDS):
            suspicious_urls.append(url)
        for sus in Config.SUSPICIOUS_DOMAINS:
            if sus in url_lower:
                suspicious_urls.append(url)
                break
    suspicious_urls = list(dict.fromkeys(suspicious_urls))
    
    return {
        'url_count': len(urls),
        'suspicious_urls': suspicious_urls,
        'shortened_urls': shortened_urls,
        'ip_urls': ip_urls,
        'all_urls': urls
    }

def analyze_subject(subject: str) -> Dict:
    if not subject:
        return {
            'is_suspicious': False,
            'flags': [],
            'keyword_count': 0,
            'severity': 'low'
        }
    
    subject_lower = subject.lower()
    flags = []
    if any(keyword in subject_lower for keyword in Config.URGENCY_KEYWORDS):
        flags.append('urgency')
    if any(keyword in subject_lower for keyword in Config.FINANCIAL_KEYWORDS):
        flags.append('financial')
    if any(keyword in subject_lower for keyword in Config.THREAT_KEYWORDS):
        flags.append('threat')
    is_suspicious = len(flags) > 0
    severity = 'low'
    if is_suspicious:
        severity = 'high' if 'threat' in flags else 'medium'
    return {
        'is_suspicious': is_suspicious,
        'flags': flags,
        'keyword_count': len(flags),
        'severity': severity
    }

def check_reply_to_spoofing(headers: Dict) -> Dict:
    from_header = headers.get("from", "")
    reply_to = headers.get("reply-to", "")
    if isinstance(from_header, list):
        from_header = from_header[0] if from_header else ""
    if isinstance(reply_to, list):
        reply_to = reply_to[0] if reply_to else ""
    if not reply_to:
        return {
            "flag": False,
            "severity": "low",
            "details": "No Reply-To header present",
            "from_domain": None,
            "reply_domain": None
        }
    from_domain = extract_email_domain(from_header)
    reply_domain = extract_email_domain(reply_to)
    if not from_domain or not reply_domain:
        return {
            "flag": False,
            "severity": "low",
            "details": "Could not extract domains for comparison",
            "from_domain": from_domain,
            "reply_domain": reply_domain
        }
    from_match = re.search(
        r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
        from_header
    )
    reply_match = re.search(
        r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
        reply_to
    )
    from_address = from_match.group(0).lower() if from_match else ""
    reply_address = reply_match.group(0).lower() if reply_match else ""
    if from_address != reply_address:
        is_free_email = any(
            provider in reply_domain
            for provider in Config.FREE_EMAIL_PROVIDERS
        )
        if from_domain != reply_domain:
            severity = "high" if is_free_email else "medium"
            details = (
                f"Reply-To domain ({reply_domain}) differs from "
                f"From domain ({from_domain})"
            )
        else:
            severity = "high" if is_free_email else "medium"
            details = (
                f"Reply-To address ({reply_address}) differs from "
                f"From address ({from_address})"
            )
        return {
            "flag": True,
            "severity": severity,
            "details": details,
            "from_domain": from_domain,
            "reply_domain": reply_domain
        }
    return {
        "flag": False,
        "severity": "low",
        "details": f"Reply-To address matches From address ({from_address})",
        "from_domain": from_domain,
        "reply_domain": reply_domain
    }

def analyze_display_name(headers: Dict) -> Dict:
    from_header = headers.get('from', '')
    if not from_header:
        return {
            'flag': False,
            'severity': 'low',
            'details': 'No From header found',
            'display_name': None,
            'domain': None
        }
    name_match = re.search(r'^"?(.+?)"?\s*<', from_header)
    if not name_match:
        return {
            'flag': False,
            'severity': 'low',
            'details': 'No display name found (email only)',
            'display_name': None,
            'domain': extract_email_domain(from_header)
        }
    display_name = name_match.group(1).strip()
    domain = extract_email_domain(from_header)
    flags = []
    name_lower = display_name.lower()
    if any(keyword in name_lower for keyword in Config.IMPERSONATION_KEYWORDS):
        flags.append('impersonation_keyword')
    if any(company in name_lower for company in Config.COMPANY_NAMES):
        flags.append('company_name')
    is_free_email = False
    if domain:
        is_free_email = any(provider in domain.lower() for provider in Config.FREE_EMAIL_PROVIDERS)
    if is_free_email and flags:
        flags.append('free_email_with_suspicious_name')
    is_suspicious = len(flags) > 0
    if not is_suspicious:
        return {
            'flag': False,
            'severity': 'low',
            'details': 'Display name appears legitimate',
            'display_name': display_name,
            'domain': domain
        }
    severity = 'high' if 'free_email_with_suspicious_name' in flags else 'medium'
    return {
        'flag': True,
        'severity': severity,
        'details': f'Display name "{display_name}" uses suspicious pattern with domain {domain}',
        'display_name': display_name,
        'domain': domain,
        'flags': flags
    }

def parse_headers(header_string: str) -> Dict[str, Union[str, List[str]]]:
    if not header_string:
        return {}

    headers: Dict[str, Union[str, List[str]]] = {}
    header_lines = header_string.splitlines()

    current_key: Optional[str] = None
    current_value: List[str] = []
    header_pattern = re.compile(r"^[^\s:]+:")

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

def analyze_headers(headers: Dict, body: str = '') -> Dict:
    findings = []
    severity_scores = {'low': 1, 'medium': 2, 'high': 3}
    max_severity = 'low'
    total_score = 0
    result1 = check_from_vs_return_path(headers)
    if result1['flag']:
        findings.append({
            'check': 'From vs Return-Path Mismatch',
            'severity': result1['severity'],
            'details': result1['details']
        })
        max_severity = max(max_severity, result1['severity'], key=lambda x: severity_scores.get(x, 0))
        total_score += severity_scores.get(result1['severity'], 0)
    result2 = check_spf_dkim(headers)
    if result2['flag']:
        findings.append({
            'check': 'SPF/DKIM Authentication',
            'severity': result2['severity'],
            'details': result2['details']
        })
        max_severity = max(max_severity, result2['severity'], key=lambda x: severity_scores.get(x, 0))
        total_score += severity_scores.get(result2['severity'], 0)
    result3 = analyze_received_chain(headers)
    if result3['flag']:
        findings.append({
            'check': 'Received Chain Analysis',
            'severity': result3['severity'],
            'details': result3['details']
        })
        max_severity = max(max_severity, result3['severity'], key=lambda x: severity_scores.get(x, 0))
        total_score += severity_scores.get(result3['severity'], 0)
    result4 = check_date_anomaly(headers)
    if result4['flag']:
        findings.append({
            'check': 'Date Anomaly',
            'severity': result4['severity'],
            'details': result4['details']
        })
        max_severity = max(max_severity, result4['severity'], key=lambda x: severity_scores.get(x, 0))
        total_score += severity_scores.get(result4['severity'], 0)
    critical_headers = ['from', 'to', 'subject', 'date']
    missing = [h for h in critical_headers if h not in headers]
    if missing:
        findings.append({
            'check': 'Missing Critical Headers',
            'severity': 'medium',
            'details': f'Missing: {", ".join(missing)}'
        })
        total_score += severity_scores.get('medium', 0)
        if max_severity == 'low':
            max_severity = 'medium'
    if body:
        url_analysis = analyze_urls(body)
        if url_analysis['suspicious_urls']:
            details = {
                'total_urls': url_analysis['url_count'],
                'suspicious_count': len(url_analysis['suspicious_urls']),
                'suspicious_urls': url_analysis['suspicious_urls'][:Config.MAX_SUSPICIOUS_URLS]
            }
            if url_analysis['shortened_urls']:
                details['shortened_urls'] = url_analysis['shortened_urls'][:Config.MAX_URLS_TO_DISPLAY]
            if url_analysis['ip_urls']:
                details['ip_urls'] = url_analysis['ip_urls'][:Config.MAX_URLS_TO_DISPLAY]
            findings.append({
                'check': 'Suspicious URLs Detected',
                'severity': 'high',
                'details': details
            })
            total_score += 3
            max_severity = 'high'
    subject_analysis = analyze_subject(headers.get('subject', ''))
    if subject_analysis['is_suspicious']:
        findings.append({
            'check': 'Suspicious Subject Line',
            'severity': subject_analysis['severity'],
            'details': {
                'flags': subject_analysis['flags'],
                'keyword_count': subject_analysis['keyword_count']
            }
        })
        total_score += severity_scores.get(subject_analysis['severity'], 0)
        if subject_analysis['severity'] == 'high' and max_severity != 'high':
            max_severity = 'high'
    reply_to_check = check_reply_to_spoofing(headers)
    if reply_to_check['flag']:
        findings.append({
            'check': 'Reply-To Spoofing',
            'severity': reply_to_check['severity'],
            'details': {
                'message': reply_to_check['details'],
                'from_domain': reply_to_check['from_domain'],
                'reply_domain': reply_to_check['reply_domain']
            }
        })
        total_score += severity_scores.get(reply_to_check['severity'], 0)
        if reply_to_check['severity'] == 'high' and max_severity != 'high':
            max_severity = 'high'
    display_name_check = analyze_display_name(headers)
    if display_name_check['flag']:
        findings.append({
            'check': 'Suspicious Display Name',
            'severity': display_name_check['severity'],
            'details': {
                'message': display_name_check['details'],
                'display_name': display_name_check['display_name'],
                'domain': display_name_check['domain']
            }
        })
        total_score += severity_scores.get(display_name_check['severity'], 0)
        if display_name_check['severity'] == 'high' and max_severity != 'high':
            max_severity = 'high'
    if total_score >= 5:
        overall_risk = 'high'
    elif total_score >= 3:
        overall_risk = 'medium'
    elif total_score >= 1:
        overall_risk = 'low'
    else:
        overall_risk = 'none'
    return {
        'summary': {
            'total_findings': len(findings),
            'max_severity': max_severity,
            'overall_risk': overall_risk,
            'risk_score': total_score
        },
        'findings': findings,
        'headers_analyzed': list(headers.keys())
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
