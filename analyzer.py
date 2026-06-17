import re
from urllib.parse import urlparse

from database import (
    is_domain_blocked,
    is_sender_blocked,
    is_domain_whitelisted
)
from reputation import check_url_reputation
from virustotal import check_virustotal


SUSPICIOUS_WORDS = [
    "urgent",
    "verify",
    "password",
    "click here",
    "account suspended",
    "bank",
    "invoice",
    "payment",
    "login",
    "confirm"
]

TRUSTED_DOMAINS = [
    "bog.ge",
    "tbcbank.ge",
    "libertybank.ge",
    "google.com",
    "microsoft.com"
]

SUSPICIOUS_TLDS = [
    ".xyz",
    ".top",
    ".click",
    ".ru",
    ".tk"
]

SUSPICIOUS_EXTENSIONS = [
    ".exe",
    ".bat",
    ".scr",
    ".zip",
    ".rar",
    ".js",
    ".vbs",
    ".cmd",
    ".ps1"
]


def extract_links(text):
    return re.findall(r"https?://\S+", text)


def get_domain(url):
    parsed = urlparse(url)
    return parsed.netloc.lower()


def extract_header_value(text, header_name):
    pattern = rf"^{header_name}:\s*(.+)$"
    match = re.search(pattern, text, re.IGNORECASE | re.MULTILINE)

    if match:
        return match.group(1).strip()

    return ""


def extract_sender_email(text):
    from_header = extract_header_value(text, "From")
    match = re.search(r"[\w\.-]+@[\w\.-]+", from_header)

    if match:
        return match.group(0).lower()

    return ""


def extract_email_domain(value):
    match = re.search(r"[\w\.-]+@([\w\.-]+)", value)

    if match:
        return match.group(1).lower()

    if "@" in value:
        return value.split("@")[-1].lower().strip()

    return ""


def analyze_blacklist(text):
    score = 0
    reasons = []

    sender = extract_sender_email(text)
    from_header = extract_header_value(text, "From")
    sender_domain = extract_email_domain(from_header)

    if sender_domain and is_domain_whitelisted(sender_domain):
        return -100, ["Whitelisted domain bypass: " + sender_domain]

    if sender and is_sender_blocked(sender):
        score += 100
        reasons.append("Blocked sender detected: " + sender)

    if sender_domain and is_domain_blocked(sender_domain):
        score += 100
        reasons.append("Blocked domain detected: " + sender_domain)

    return score, reasons


def analyze_headers(text):
    score = 0
    reasons = []

    from_header = extract_header_value(text, "From")
    return_path = extract_header_value(text, "Return-Path")
    reply_to = extract_header_value(text, "Reply-To")
    spf = extract_header_value(text, "SPF")
    dkim = extract_header_value(text, "DKIM")
    dmarc = extract_header_value(text, "DMARC")

    from_domain = extract_email_domain(from_header)
    return_domain = extract_email_domain(return_path)
    reply_domain = extract_email_domain(reply_to)

    if from_domain and return_domain and from_domain != return_domain:
        score += 20
        reasons.append("Header mismatch: From domain differs from Return-Path domain")

    if from_domain and reply_domain and from_domain != reply_domain:
        score += 15
        reasons.append("Header mismatch: From domain differs from Reply-To domain")

    if spf.lower() == "fail":
        score += 20
        reasons.append("SPF authentication failed")

    if dkim.lower() == "fail":
        score += 20
        reasons.append("DKIM authentication failed")

    if dmarc.lower() == "fail":
        score += 25
        reasons.append("DMARC authentication failed")

    return score, reasons


def analyze_domain(domain):
    score = 0
    reasons = []

    if is_domain_blocked(domain):
        score += 100
        reasons.append("Blocked linked domain detected: " + domain)

    if domain.count("-") >= 2:
        score += 15
        reasons.append("Domain contains multiple hyphens")

    if domain.count(".") >= 3:
        score += 15
        reasons.append("Suspicious number of subdomains")

    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            score += 20
            reasons.append("Suspicious top-level domain: " + tld)

    for trusted in TRUSTED_DOMAINS:
        trusted_name = trusted.split(".")[0]

        if trusted_name in domain and not domain.endswith(trusted):
            score += 25
            reasons.append("Possible lookalike domain: " + domain)

    return score, reasons


def analyze_attachments(lower_text):
    score = 0
    reasons = []

    attachment_matches = re.findall(
        r"[\w\-.]+\.(exe|bat|scr|zip|rar|js|vbs|cmd|ps1)",
        lower_text
    )

    if len(attachment_matches) > 0:
        score += 10
        reasons.append("Email contains attachment references")

    for ext in SUSPICIOUS_EXTENSIONS:
        if ext in lower_text:
            score += 25
            reasons.append("Suspicious attachment detected: " + ext)

    return score, reasons


def analyze_email(text):
    score = 0
    reasons = []

    lower = text.lower()

    blacklist_score, blacklist_reasons = analyze_blacklist(text)
    score += blacklist_score
    reasons.extend(blacklist_reasons)

    header_score, header_reasons = analyze_headers(text)
    score += header_score
    reasons.extend(header_reasons)

    for word in SUSPICIOUS_WORDS:
        if word in lower:
            score += 5
            reasons.append("Suspicious word: " + word)

    links = extract_links(text)

    if len(links) > 0:
        score += 10
        reasons.append("Contains link(s)")

    for link in links:
        domain = get_domain(link)
        domain_score, domain_reasons = analyze_domain(domain)
        score += domain_score
        reasons.extend(domain_reasons)

    reputation_result = check_url_reputation(links)
    score += reputation_result["score"]
    reasons.extend(reputation_result["reasons"])

    vt_result = check_virustotal(links)
    score += vt_result["score"]
    reasons.extend(vt_result["reasons"])

    attachment_score, attachment_reasons = analyze_attachments(lower)
    score += attachment_score
    reasons.extend(attachment_reasons)

    score = max(score, 0)
    score = min(score, 100)

    return {
        "score": score,
        "reasons": reasons,
        "links": links,
        "breakdown": {
            "blacklist": blacklist_score,
            "headers": header_score,
            "attachments": attachment_score,
            "reputation": reputation_result["score"],
            "virustotal": vt_result["score"]
        }
    }
