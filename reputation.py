BLACKLISTED_DOMAINS = [
    "fake-bank.com",
    "phishing-login.com",
    "malware-download.com",
    "bog.ge.com",
    "secure-login-update.xyz"
]

SUSPICIOUS_KEYWORDS = [
    "login",
    "verify",
    "secure",
    "update",
    "account",
    "bank",
    "password"
]

def check_url_reputation(links):
    score = 0
    reasons = []

    for link in links:
        lower = link.lower()

        for domain in BLACKLISTED_DOMAINS:
            if domain in lower:
                score += 40
                reasons.append("Blacklisted domain detected: " + domain)

        for keyword in SUSPICIOUS_KEYWORDS:
            if keyword in lower:
                score += 5
                reasons.append("Suspicious keyword in URL: " + keyword)

    return {
        "score": min(score, 100),
        "reasons": reasons
    }
