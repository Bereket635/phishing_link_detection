# =====================================
# Simple Phishing Link Detector
# Android  Supported
# =====================================

import re
from urllib.parse import urlparse
import time 
import sys

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
    "password",
    "free-internet",
    "reward",
    "security",
    "win",
    "won"
]

# URL shorteners
shorteners = [
    "bit.ly",
    "tinyurl.com",
    "goo.gl",
    "t.co",
    ".xyz"
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
print("|========°Phishing Link Detector°========|")
def type_out_text(text, delay = 0.05):
    for char in text:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(delay)

text_to_type = "Phishing Link Detector Started............ Enter URL and press Enter to check it for suspiciousness or Press ENTER without input to exit...\n"

type_out_text(text_to_type, delay = 0.05)
    


while True:
    url = input("Enter URL to scan: ")
    
    #Exit condition
    if url == "":
        print("Exiting phishing link detector...")
        break 

    detect_phishing(url)