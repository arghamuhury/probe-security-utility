async function checkURL() {
    const url = document.getElementById("urlInput").value.trim();

    if (!url) {
        delayedPopup("Input Error", "URL is required for analysis.");
        return;
    }
    
    try {
        const res = await fetch("/check-url", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url })
        });

        const data = await res.json();

        if (data.details && data.details.length > 0) {
            showPopup(
                data.message,
                data.details.join("\n")
            );
        } else {
            showPopup("Result", data.message);
        }
    } catch (err) {
        showPopup("Error", "Unable to check URL. Please try again.");
    }
}

async function generateHash() {
    const file = document.getElementById("fileInput").files[0];

    if (!file) {
        delayedPopup("File Required", "Please select a file first.");
        return;
    }


    const formData = new FormData();
    formData.append("file", file);

    const res = await fetch("/generate-hash", {
        method: "POST",
        body: formData
    });

    const data = await res.json();

    if (data.hash) {
        showPopup("Hash Generated", data.hash);
    } else {
        showPopup("Result", data.message);
    }
}


async function verifyHash() {
    const file = document.getElementById("fileInput").files[0];

    if (!file) {
        delayedPopup("File Required", "Please select a file first.");
        return;
    }

    const formData = new FormData();
    formData.append("file", file);

    const res = await fetch("/verify-hash", {
        method: "POST",
        body: formData
    });

    const data = await res.json();
    showPopup("Verification Result", data.message);
}

function checkPasswordStrength() {
    const password = document.getElementById("passwordInput").value;
    const bar = document.getElementById("strengthBar");
    const text = document.getElementById("strengthText");

    let score = 0;

    if (password.length >= 8) score++;
    if (/[A-Z]/.test(password)) score++;
    if (/[0-9]/.test(password)) score++;
    if (/[^A-Za-z0-9]/.test(password)) score++;

    if (password.length === 0) {
        bar.style.width = "0%";
        bar.style.background = "transparent";
        text.textContent = "";
        return;
    }

    if (score <= 1) {
        bar.style.width = "33%";
        bar.style.background = "#dc2626";
        text.textContent = "Weak password";
    } 
    else if (score <= 3) {
        bar.style.width = "66%";
        bar.style.background = "#f59e0b";
        text.textContent = "Moderate password";
    } 
    else {
        bar.style.width = "100%";
        bar.style.background = "#16a34a";
        text.textContent = "Strong password";
    }
}

async function encryptFile() {
    const file = document.getElementById("encryptFileInput").files[0];
    const password = document.getElementById("encPassword").value;

    if (!file || !password) {
        showPopup("Input Required", "File and password are required.");
        return;
    }

    const formData = new FormData();
    formData.append("file", file);
    formData.append("password", password);

    const res = await fetch("/encrypt-file", {
        method: "POST",
        body: formData
    });

    if (!res.ok) {
        showPopup("Error", "Encryption failed");
        return;
    }

    const blob = await res.blob();
    downloadBlob(blob, file.name + ".enc");
}

async function decryptFile() {
    const file = document.getElementById("encryptFileInput").files[0];
    const password = document.getElementById("encPassword").value;

    if (!file || !password) {
        showPopup("Input Required", "File and password are required.");
        return;
    }

    const formData = new FormData();
    formData.append("file", file);
    formData.append("password", password);

    const res = await fetch("/decrypt-file", {
        method: "POST",
        body: formData
    });

    if (!res.ok) {
        showPopup("Error", "Wrong password or invalid file");
        return;
    }

    const blob = await res.blob();
    downloadBlob(blob, file.name.replace(".enc", ""));
}

function generatePassword(length = 16) {
    const useUpper = document.getElementById("optUpper").checked;
    const useLower = document.getElementById("optLower").checked;
    const useNumbers = document.getElementById("optNumbers").checked;
    const useSymbols = document.getElementById("optSymbols").checked;

    if (!useUpper && !useLower && !useNumbers && !useSymbols) {
        showPopup("Selection Required", "Select at least one character type.");
        return;
    }

    const upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const lower = "abcdefghijklmnopqrstuvwxyz";
    const numbers = "0123456789";
    const symbols = "!@#$%^&*()-_=+[]{}<>?";

    let pool = "";
    let password = "";

    if (useUpper) {
        pool += upper;
        password += upper[Math.floor(Math.random() * upper.length)];
    }
    if (useLower) {
        pool += lower;
        password += lower[Math.floor(Math.random() * lower.length)];
    }
    if (useNumbers) {
        pool += numbers;
        password += numbers[Math.floor(Math.random() * numbers.length)];
    }
    if (useSymbols) {
        pool += symbols;
        password += symbols[Math.floor(Math.random() * symbols.length)];
    }

    for (let i = password.length; i < length; i++) {
        password += pool[Math.floor(Math.random() * pool.length)];
    }

    password = password
        .split("")
        .sort(() => 0.5 - Math.random())
        .join("");

    document.getElementById("generatedPassword").value = password;
}

document.getElementById("copyBtn").addEventListener("click", () => {
    const pwd = document.getElementById("generatedPassword").value;
    if (!pwd) return;

    navigator.clipboard.writeText(pwd);

    const status = document.getElementById("copyStatus");
    status.classList.remove("hidden");

    setTimeout(() => {
        status.classList.add("hidden");
    }, 1500);
});

function copyPassword() {
    const input = document.getElementById("generatedPassword");
    const text = input.value;

    if (!text) return;

    navigator.clipboard.writeText(text).then(() => {
        const status = document.getElementById("copyStatus");
        if (status) {
            status.classList.remove("hidden");
            setTimeout(() => {
                status.classList.add("hidden");
            }, 1500);
        }
    }).catch(err => {
        console.error("Clipboard error:", err);
        alert("Copy failed. Try manually selecting the text.");
    });
}

function delayedPopup(title, message, delay = 250) {
    setTimeout(() => {
        showPopup(title, message);
    }, delay);
}

function showPopup(title, message) {
    document.getElementById("popupTitle").innerText = title;

    const msg = document.getElementById("popupMessage");

    if (message.length > 60) {
        msg.innerHTML = `<code style="white-space: pre-line;">${message}</code>`;
    } else {
        msg.innerText = message;
    }

    document.getElementById("popup").classList.remove("hidden");
}

function closePopup() {
    document.getElementById("popup").classList.add("hidden");
}

function downloadBlob(blob, filename) {
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    a.click();
    window.URL.revokeObjectURL(url);
}

async function deriveKeyFromPassword(password, salt) {
    const enc = new TextEncoder();

    const baseKey = await crypto.subtle.importKey(
        "raw",
        enc.encode(password),
        "PBKDF2",
        false,
        ["deriveKey"]
    );

    return crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: salt,
            iterations: 100000,
            hash: "SHA-256"
        },
        baseKey,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt", "decrypt"]
    );
}

function showSecureResult(text, type = "safe") {
    const box = document.getElementById("secureResult");
    box.textContent = text;
    box.className = `secure-output ${type}`;
    box.classList.remove("hidden");
    resetSecureTextarea();
}

async function encryptText() {
    const text = document.getElementById("secureText").value;
    const password = document.getElementById("securePassword").value;

    if (!text || !password) {
        showSecureResult("Text and password are required.", "warning");
        return;
    }

    const enc = new TextEncoder();
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await deriveKeyFromPassword(password, salt);

    const encrypted = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv },
        key,
        enc.encode(text)
    );

    const payload = {
        salt: Array.from(salt),
        iv: Array.from(iv),
        data: Array.from(new Uint8Array(encrypted))
    };

    showSecureResult(btoa(JSON.stringify(payload)), "safe");
}

async function decryptText() {
    const input = document.getElementById("secureText").value;
    const password = document.getElementById("securePassword").value;

    if (!input || !password) {
        showSecureResult("Encrypted text and password are required.", "warning");
        return;
    }

    try {
        const decoded = JSON.parse(atob(input));
        const salt = new Uint8Array(decoded.salt);
        const iv = new Uint8Array(decoded.iv);
        const data = new Uint8Array(decoded.data);

        const key = await deriveKeyFromPassword(password, salt);

        const decrypted = await crypto.subtle.decrypt(
            { name: "AES-GCM", iv: iv },
            key,
            data
        );

        showSecureResult(new TextDecoder().decode(decrypted), "safe");
    } catch {
        showSecureResult("Decryption failed. Wrong password or invalid data.", "danger");
    }
}

const secureText = document.getElementById("secureText");

secureText.addEventListener("input", () => {
    secureText.style.height = "auto";
    secureText.style.height = secureText.scrollHeight + "px";
});

function resetSecureTextarea() {
    const ta = document.getElementById("secureText");
    ta.value = "";
    ta.style.height = "44px";
}
