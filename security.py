import hashlib, json, os, re, requests
from urllib.parse import urlparse

def generate_file_hash(file_path):
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)
    return sha256.hexdigest()

def rule_based_url_check(url):
    score = 0
    reasons = []

    if len(url) > 75:
        score += 1; reasons.append("URL too long")
    if "@" in url:
        score += 1; reasons.append("Contains '@'")
    if not url.startswith("https://"):
        score += 1; reasons.append("No HTTPS")

    domain = urlparse(url).netloc
    if re.match(r"\d+\.\d+\.\d+\.\d+", domain):
        score += 1; reasons.append("IP-based URL")

    return score, reasons

def urlhaus_check(url):
    api = "https://urlhaus-api.abuse.ch/v1/url/"
    try:
        r = requests.post(api, data={"url": url})
        return r.json().get("query_status") == "ok"
    except:
        return False