# =====================================
# Simple Phishing Link Detector
# Android Supported
# =====================================

import re
from urllib.parse import urlparse

# Suspicious keywords
phishing_keywords = [
    "login",
    "verify",
    "update",
    "secure",
    "bank",
    "paypal",
    "free",
    "bonus",
    "gift",
    "password"
]

# URL shorteners
shorteners = [
    "bit.ly",
    "tinyurl.com",
    "goo.gl",
    "t.co"
]


def detect_phishing(url):

    score = 0
    reasons = []

    parsed = urlparse(url)
    domain = parsed.netloc.lower()

    # 1. Detect insecure HTTP
    if url.startswith("http://"):
        score += 2
        reasons.append("Uses insecure HTTP instead of HTTPS")

    # 2. Detect IP address in URL
    ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"

    if re.search(ip_pattern, domain):
        score += 2
        reasons.append("Uses IP address instead of domain")

    # 3. Too many subdomains
    if domain.count(".") > 3:
        score += 1
        reasons.append("Too many subdomains")

    # 4. Suspicious symbols
    if "@" in url or "-" in domain:
        score += 1
        reasons.append("Contains suspicious symbols")

    # 5. Phishing keywords
    for word in phishing_keywords:
        if word in url.lower():
            score += 1
            reasons.append(f"Contains suspicious keyword: {word}")

    # 6. URL shorteners
    for short in shorteners:
        if short in domain:
            score += 2
            reasons.append("Uses shortened URL")

    # =============================
    # Final Result
    # =============================

    print("\n==============================")
    print("URL Analysis Result")
    print("==============================")

    print(f"URL: {url}")
    print(f"Risk Score: {score}")

    if score >= 4:
        print("\n[ALERT] HIGH RISK: Possible phishing link!")

    elif score >= 2:
        print("\n[WARNING] Suspicious link.")

    else:
        print("\n[SAFE] Link looks mostly safe.")

    # Print reasons
    if reasons:
        print("\nReasons:")
        for reason in reasons:
            print("-", reason)


# =============================
# User Input
# =============================

url = input("Enter URL to scan: ")

detect_phishing(url)