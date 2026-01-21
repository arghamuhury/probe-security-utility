from flask import Flask, render_template, request, jsonify
import hashlib, json, os, re
import requests
from urllib.parse import urlparse
from werkzeug.utils import secure_filename
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidKey
import secrets
import io
from flask import send_file

app = Flask(__name__)

SAFE_BROWSING_API_KEY = "AIzaSyCVJoUdxnHbbEkgeVXRmQGNAmCGGSDEAHs"

if not SAFE_BROWSING_API_KEY:
    raise RuntimeError("Google Safe Browsing API key not configured")

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,              # 256-bit key
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def rule_based_url_check(url):
    score = 0
    reasons = []

    if len(url) > 75:
        reasons.append("URL is unusually long")

    if "@" in url:
        reasons.append("Contains '@' symbol")

    if url.startswith("http://"):
        reasons.append("Uses insecure HTTP")


    domain = urlparse(url).netloc
    if re.match(r"\d+\.\d+\.\d+\.\d+", domain):
        reasons.append("IP-based URL")

    return reasons

def urlhaus_check(url):
    try:
        r = requests.post(
            "https://urlhaus-api.abuse.ch/v1/url/",
            data={"url": url},
            timeout=5
        )
        return r.json().get("query_status") == "ok"
    except:
        return False

def google_safe_browsing_check(url):
    endpoint = (
        "https://safebrowsing.googleapis.com/v4/threatMatches:find"
        f"?key={SAFE_BROWSING_API_KEY}"
    )

    payload = {
        "client": {
            "clientId": "probe-security",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING"
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }

    try:
        r = requests.post(endpoint, json=payload, timeout=5)
        print("Safe Browsing status:", r.status_code)
        print("Safe Browsing response:", r.text)

        data = r.json()
        return "matches" in data

    except Exception as e:
        print("Safe Browsing exception:", e)
        return False


UPLOAD_FOLDER = "uploads"
HASH_DB = "hashes.json"

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def generate_file_hash(path):
    sha256 = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)
    return sha256.hexdigest()

def is_valid_url(url: str) -> bool:
    # Must start with http:// or https://
    if not re.match(r"^https?://", url):
        return False

    parsed = urlparse(url)

    if not parsed.netloc:
        return False

    if "." not in parsed.netloc:
        return False

    return True

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/check-url", methods=["POST"])
def check_url():
    data = request.json
    url = data.get("url", "").strip()

    if not is_valid_url(url):
        return jsonify({
            "status": "error",
            "message": "Invalid URL format. Please enter a valid URL (including http:// or https://)."
        })

    if not url:
        return jsonify({
            "status": "error",
            "message": "URL required"
        })

    if google_safe_browsing_check(url):
        return jsonify({
            "status": "danger",
            "message": "Malicious URL detected\n(Google Safe Browsing)"
        })

    if urlhaus_check(url):
        return jsonify({
            "status": "danger",
            "message": "Malicious URL detected\n(Threat Intelligence Feed)"
        })

    reasons = rule_based_url_check(url)

    if not reasons:
        return jsonify({
            "status": "safe",
            "message": "URL is SAFE"
        })
    else:
        return jsonify({
            "status": "warning",
            "message": "Potentially suspicious URL",
            "details": reasons
        })

@app.route("/generate-hash", methods=["POST"])
def generate_hash():
    if "file" not in request.files:
        return jsonify({"status": "error", "message": "No file uploaded"})

    file = request.files["file"]
    if file.filename == "":
        return jsonify({"status": "error", "message": "No file selected"})

    filename = secure_filename(file.filename)
    filepath = os.path.join(UPLOAD_FOLDER, filename)
    file.save(filepath)

    file_hash = generate_file_hash(filepath)

    # Save hash
    with open(HASH_DB, "r") as f:
        data = json.load(f)

    data[filename] = file_hash

    with open(HASH_DB, "w") as f:
        json.dump(data, f, indent=4)

    return jsonify({
        "status": "success",
        "message": "Hash generated",
        "hash": file_hash
    })

@app.route("/verify-hash", methods=["POST"])
def verify_hash():
    if "file" not in request.files:
        return jsonify({"status": "error", "message": "No file uploaded"})

    file = request.files["file"]
    filename = secure_filename(file.filename)
    filepath = os.path.join(UPLOAD_FOLDER, filename)
    file.save(filepath)

    with open(HASH_DB, "r") as f:
        data = json.load(f)

    if filename not in data:
        return jsonify({
            "status": "warning",
            "message": "No stored hash for this file"
        })

    current_hash = generate_file_hash(filepath)

    if current_hash == data[filename]:
        return jsonify({
            "status": "success",
            "message": "File integrity verified"
        })
    else:
        return jsonify({
            "status": "danger",
            "message": "File has been modified"
        })

@app.route("/encrypt-file", methods=["POST"])
def encrypt_file():
    file = request.files.get("file")
    password = request.form.get("password")

    if not file or not password:
        return jsonify({"message": "File and password required"}), 400

    data = file.read()

    salt = secrets.token_bytes(16)
    iv = secrets.token_bytes(16)
    key = derive_key(password, salt)

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()

    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    encrypted = encryptor.update(padded_data) + encryptor.finalize()

    output = salt + iv + encrypted

    return send_file(
        io.BytesIO(output),
        as_attachment=True,
        download_name=file.filename + ".enc"
    )

@app.route("/decrypt-file", methods=["POST"])
def decrypt_file():
    file = request.files.get("file")
    password = request.form.get("password")

    if not file or not password:
        return jsonify({"message": "File and password required"}), 400

    data = file.read()

    salt = data[:16]
    iv = data[16:32]
    encrypted = data[32:]

    try:
        key = derive_key(password, salt)

        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        padded_plain = decryptor.update(encrypted) + decryptor.finalize()

        unpadder = padding.PKCS7(128).unpadder()
        plain = unpadder.update(padded_plain) + unpadder.finalize()

    except Exception:
        return jsonify({"message": "Invalid password or corrupted file"}), 400

    return send_file(
        io.BytesIO(plain),
        as_attachment=True,
        download_name=file.filename.replace(".enc", "")
    )

if __name__ == "__main__":
    app.run(debug=True)
