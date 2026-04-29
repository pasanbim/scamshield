from fastapi import FastAPI, Request, HTTPException
import psycopg
from psycopg.rows import dict_row
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
import uuid

import os
import re
import sys
import time
import json
import pickle
from pathlib import Path
from typing import Optional, Any
from urllib.parse import urlparse, parse_qs, unquote
from difflib import SequenceMatcher
from html.parser import HTMLParser

import email as email_lib
import requests
import pandas as pd
from google import genai

from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    classification_report,
    confusion_matrix,
)
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline


# ============================================================
# CONFIG
# ============================================================

CSV_PATH = "phishing_email.csv"
MODEL_PATH = "scamshield_model.pkl"
TEXT_COL = "text_combined"
LABEL_COL = "label"
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
GOOGLE_API_KEY = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY")
WHOISJSON_API_KEY = os.getenv("WHOISJSON_API_KEY", "c1f293201ca80aa6308a04d7b87a8249a683812866eb3d2eb55bf9cf89718a16")
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://postgres.lbounrtpongoaizuzktw:28gI51Im4cwKP7Jw@aws-0-eu-west-1.pooler.supabase.com:5432/postgres")


SAFE_BROWSING_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

REQUEST_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    )
}

KNOWN_BRANDS = [
    "google.com",
    "microsoft.com",
    "apple.com",
    "amazon.com",
    "paypal.com",
    "github.com",
    "openai.com",
    "facebook.com",
    "instagram.com",
    "linkedin.com",
    "netflix.com",
    "dropbox.com",
    "outlook.com",
    "gmail.com",
    "bankofamerica.com",
    "barclays.co.uk",
    "hsbc.co.uk",
    "lloydsbank.co.uk",
    "natwest.com",
    "spaceship.com",
]

CATEGORY_KEYWORDS = {
    "DELIVERY_SCAM": [
        "delivery", "consignment", "parcel", "shipment", "courier", "package",
        "dispatch", "pre-alert", "pre alert", "customs", "track your",
        "tracking number", "dhl", "fedex", "ups", "royal mail", "evri", "xdp"
    ],
    "PHISHING": [
        "verify your", "confirm your", "update your", "security alert",
        "login", "sign in", "password", "credential", "account suspended",
        "unauthorized", "unusual activity", "click here"
    ],
    "FINANCIAL_FRAUD": [
        "bank", "invoice", "payment", "refund", "tax", "hmrc", "irs",
        "transfer", "wire", "crypto", "bitcoin", "wallet", "sort code"
    ],
    "ADVANCE_FEE_SCAM": [
        "donation", "beneficiary", "inheritance", "fund", "lottery",
        "you have won", "reward", "claim your", "usd", "million"
    ],
    "JOB_SCAM": [
        "job offer", "work from home", "remote position", "weekly pay",
        "no experience", "earn per day", "hiring"
    ],
    "MALWARE": [
        "attachment", "download", "enable macros", "macro", "installer",
        "exe", "zip file", "open the file"
    ]
}

IMAGE_EXTENSIONS = {".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg", ".ico", ".bmp"}


# ============================================================
# TEXT / ML
# ============================================================

def clean_text(text: str) -> str:
    text = str(text).lower()
    text = re.sub(r"http\S+|www\S+", " URL ", text)
    text = re.sub(r"\S+@\S+", " EMAIL ", text)
    text = re.sub(r"[^a-z0-9\s$£€]", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text


def load_dataset(csv_path: str) -> pd.DataFrame:
    df = pd.read_csv(csv_path)
    required = {TEXT_COL, LABEL_COL}
    missing = required - set(df.columns)
    if missing:
        raise ValueError(f"Missing required columns: {missing}")

    df = df[[TEXT_COL, LABEL_COL]].copy()
    df[TEXT_COL] = df[TEXT_COL].fillna("").astype(str)
    df[LABEL_COL] = df[LABEL_COL].astype(int)
    df["clean_text"] = df[TEXT_COL].apply(clean_text)
    return df


def train_model(csv_path: str = CSV_PATH, model_path: str = MODEL_PATH) -> None:
    df = load_dataset(csv_path)

    X = df["clean_text"]
    y = df[LABEL_COL]

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.2,
        random_state=42,
        stratify=y,
    )

    model = Pipeline([
        ("tfidf", TfidfVectorizer(max_features=5000, ngram_range=(1, 2))),
        ("clf", LogisticRegression(max_iter=1000)),
    ])

    model.fit(X_train, y_train)
    preds = model.predict(X_test)

    print("\n" + "=" * 60)
    print("TF-IDF + Logistic Regression")
    print("=" * 60)
    print("Accuracy :", round(accuracy_score(y_test, preds), 4))
    print("Precision:", round(precision_score(y_test, preds, zero_division=0), 4))
    print("Recall   :", round(recall_score(y_test, preds, zero_division=0), 4))
    print("F1 Score :", round(f1_score(y_test, preds, zero_division=0), 4))
    print("\nClassification Report:")
    print(classification_report(y_test, preds, zero_division=0))
    print("Confusion Matrix:")
    print(confusion_matrix(y_test, preds))

    with open(model_path, "wb") as f:
        pickle.dump(model, f)

    print(f"\nSaved model to {model_path}")


def load_model(model_path: str = MODEL_PATH):
    if not Path(model_path).exists():
        raise FileNotFoundError(
            f"Model file not found: {model_path}\n"
            f"Run: python main.py train"
        )
    with open(model_path, "rb") as f:
        return pickle.load(f)


# ============================================================
# CONTENT FEATURES
# ============================================================

def extract_rule_features(text: str) -> dict[str, bool]:
    t = text.lower()

    return {
        "has_url": bool(re.search(r"(http|www|url)", t)),
        "has_email": bool(re.search(r"\bemail\b|@\w+\.", t)),
        "has_money_amount": bool(re.search(r"(\$|£|€|usd|gbp|eur)\s?\d+", t)),
        "has_large_number": bool(re.search(r"\b\d{5,}\b|\b\d+\s?(million|m|billion|bn)\b", t)),
        "has_urgency": bool(re.search(r"\b(urgent|immediately|asap|within 24 hours|act now|final notice)\b", t)),
        "has_account_terms": bool(re.search(r"\b(account|bank|payment|invoice|transaction|security)\b", t)),
        "has_credential_terms": bool(re.search(r"\b(login|sign in|password|verify|verification|reset)\b", t)),
        "has_action_request": bool(re.search(r"\b(click|confirm|reply|respond|contact|open attachment|download)\b", t)),
        "has_reward_terms": bool(re.search(r"\b(prize|winner|won|lottery|donation|beneficiary|inheritance|fund)\b", t)),
        "has_threat_terms": bool(re.search(r"\b(suspended|blocked|locked|terminated|penalty|legal action)\b", t)),
        "has_free_mail_domain": bool(re.search(r"\b(gmail|outlook|yahoo|hotmail)\b", t)),
        "has_forwarded_marker": bool(re.search(r"\b(forwarded message|fwd)\b", t)),
        "many_exclamations": text.count("!") >= 3,
        "many_caps_words": len(re.findall(r"\b[A-Z]{4,}\b", text)) >= 3,
        "short_message": len(t.split()) < 25,
    }


def content_rule_score(text: str) -> int:
    f = extract_rule_features(text)
    score = 0

    if f["has_url"]:
        score += 2
    if f["has_email"]:
        score += 1
    if f["has_money_amount"]:
        score += 2
    if f["has_large_number"]:
        score += 2
    if f["has_urgency"]:
        score += 2
    if f["has_account_terms"]:
        score += 2
    if f["has_credential_terms"]:
        score += 3
    if f["has_action_request"]:
        score += 1
    if f["has_reward_terms"]:
        score += 2
    if f["has_threat_terms"]:
        score += 2
    if f["has_free_mail_domain"]:
        score += 1
    if f["has_forwarded_marker"]:
        score += 1
    if f["many_exclamations"]:
        score += 1
    if f["many_caps_words"]:
        score += 1
    if f["short_message"]:
        score += 1

    if f["has_url"] and f["has_credential_terms"]:
        score += 2
    if f["has_money_amount"] and f["has_reward_terms"]:
        score += 2
    if f["has_urgency"] and f["has_action_request"]:
        score += 2
    if f["has_free_mail_domain"] and f["has_reward_terms"]:
        score += 1

    return min(score, 30)


# ============================================================
# URL HELPERS
# ============================================================

def normalize_url(url: str) -> str:
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url


def get_hostname(url: str) -> str:
    parsed = urlparse(url)
    host = parsed.netloc.lower().strip()
    if host.startswith("www."):
        host = host[4:]
    return host


def get_registered_like_domain(hostname: str) -> str:
    parts = hostname.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return hostname


def extract_embedded_url(url: str) -> Optional[str]:
    try:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=False)
        for key in ("url", "redirect", "u", "link", "to", "dest", "target", "r", "ref", "goto"):
            if key in params:
                candidate = unquote(params[key][0])
                if candidate.startswith(("http://", "https://")):
                    return candidate
    except Exception:
        return None
    return None


def resolve_via_http(url: str, timeout: int = 5) -> dict[str, Any]:
    def _follow(method: str):
        return requests.request(
            method,
            url,
            allow_redirects=True,
            timeout=timeout,
            headers=REQUEST_HEADERS,
        )

    try:
        resp = _follow("HEAD")
        if resp.status_code in (405, 501) or resp.url == url:
            resp = _follow("GET")
    except requests.exceptions.Timeout:
        raise
    except requests.RequestException:
        resp = _follow("GET")

    chain = [r.url for r in resp.history] + [resp.url]
    return {
        "final_url": resp.url,
        "redirect_chain": chain,
        "hops": len(resp.history),
        "status_code": resp.status_code,
    }


def resolve_url(url: str) -> dict[str, Any]:
    result = {
        "original_url": url,
        "final_url": url,
        "redirect_chain": [url],
        "resolution_method": "none",
        "hops": 0,
        "error": None,
    }

    embedded = extract_embedded_url(url)
    if embedded:
        result["final_url"] = embedded
        result["redirect_chain"] = [url, embedded]
        result["resolution_method"] = "embedded_param"
        result["hops"] = 1
        try:
            http_result = resolve_via_http(embedded)
            if http_result["final_url"] != embedded:
                result["final_url"] = http_result["final_url"]
                result["redirect_chain"] = [url] + http_result["redirect_chain"]
                result["hops"] = len(result["redirect_chain"]) - 1
                result["resolution_method"] = "embedded_param+http_follow"
        except Exception:
            pass
        return result

    try:
        http_result = resolve_via_http(url)
        result["final_url"] = http_result["final_url"]
        result["redirect_chain"] = http_result["redirect_chain"]
        result["hops"] = http_result["hops"]
        result["resolution_method"] = "http_follow"
    except requests.RequestException as e:
        result["error"] = str(e)

    return result


# ============================================================
# TYPOSQUATTING
# ============================================================

def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)

    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        curr = [i]
        for j, cb in enumerate(b, start=1):
            ins = curr[j - 1] + 1
            dele = prev[j] + 1
            sub = prev[j - 1] + (ca != cb)
            curr.append(min(ins, dele, sub))
        prev = curr
    return prev[-1]


def looks_like_typosquat(hostname: str, known_domains: list[str]) -> dict[str, Any]:
    domain = get_registered_like_domain(hostname)

    if domain in known_domains:
        return {
            "is_typosquat_suspected": False,
            "matched_brand": domain,
            "reason": "Exact match to known domain",
            "score": 0.0,
        }

    sld = domain.split(".")[0] if "." in domain else domain
    best = None
    best_score = -1.0

    for candidate in known_domains:
        candidate_sld = candidate.split(".")[0]
        edit_distance = levenshtein(sld, candidate_sld)
        similarity = SequenceMatcher(None, sld, candidate_sld).ratio()

        suspicious_patterns = [
            bool(re.search(r"[0-9]", sld)),
            "-" in sld,
            sld.replace("0", "o").replace("1", "l").replace("3", "e") == candidate_sld,
        ]

        score = 0.0
        if edit_distance == 1:
            score += 0.6
        elif edit_distance == 2:
            score += 0.25
        if similarity >= 0.88:
            score += 0.3
        elif similarity >= 0.80:
            score += 0.15
        if any(suspicious_patterns):
            score += 0.1
        if "." in domain and "." in candidate and domain.split(".")[-1] != candidate.split(".")[-1]:
            score += 0.05

        if score > best_score:
            best_score = score
            best = {
                "is_typosquat_suspected": score >= 0.6,
                "matched_brand": candidate,
                "reason": (
                    f"similarity={similarity:.2f}, "
                    f"edit_distance={edit_distance}, "
                    f"suspicious_patterns={any(suspicious_patterns)}"
                ),
                "score": round(score, 2),
            }

    return best or {
        "is_typosquat_suspected": False,
        "matched_brand": None,
        "reason": "No close match found",
        "score": 0.0,
    }


# ============================================================
# SAFE BROWSING
# ============================================================

def check_google_safe_browsing(url: str) -> dict[str, Any]:
    if not GOOGLE_API_KEY:
        return {"disabled": True, "reason": "No GOOGLE_SAFE_BROWSING_API_KEY set"}

    response = requests.post(
        SAFE_BROWSING_URL,
        params={"key": GOOGLE_API_KEY},
        json={
            "client": {"clientId": "scamshield", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": [
                    "MALWARE",
                    "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE",
                    "POTENTIALLY_HARMFUL_APPLICATION",
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}],
            },
        },
        timeout=20,
    )
    response.raise_for_status()
    return response.json()


# ============================================================
# WHOIS / SSL (WhoisJSON)
# ============================================================

def check_whois_ssl(domain: str) -> dict[str, Any]:
    if not WHOISJSON_API_KEY:
         return {"disabled": True, "reason": "No WHOISJSON_API_KEY set"}
         
    try:
         headers = {"Authorization": f"TOKEN={WHOISJSON_API_KEY}"}
         response = requests.get(f"https://whoisjson.com/api/v1/ssl-cert-check?domain={domain}", headers=headers, timeout=5)
         if response.status_code == 200:
             return response.json()
         return {"error": f"API returned status {response.status_code}"}
    except Exception as e:
         return {"error": str(e)}

def check_whois_domain(domain: str) -> dict[str, Any]:
    if not WHOISJSON_API_KEY:
         return {"disabled": True, "reason": "No WHOISJSON_API_KEY set"}
         
    try:
         headers = {"Authorization": f"TOKEN={WHOISJSON_API_KEY}"}
         response = requests.get(f"https://whoisjson.com/api/v1/whois?domain={domain}&_forceRefresh=1", headers=headers, timeout=5)
         if response.status_code == 200:
             return response.json()
         return {"error": f"API returned status {response.status_code}"}
    except Exception as e:
         return {"error": str(e)}


# ============================================================
# URL ANALYSIS
# ============================================================

def analyze_url(url: str) -> dict[str, Any]:
    url = normalize_url(url)
    resolution = resolve_url(url)
    final_url = resolution["final_url"]
    hostname = get_hostname(final_url)

    result = {
        "input_url": url,
        "final_url": final_url,
        "redirect_chain": resolution["redirect_chain"],
        "resolution_method": resolution["resolution_method"],
        "hops": resolution["hops"],
        "resolution_error": resolution["error"],
        "hostname": hostname,
        "typosquat": None,
        "google_safe_browsing": None,
        "whois_domain": None,
        "whois_ssl": None,
        "final_verdict": "UNKNOWN",
        "reasons": [],
    }

    if resolution["error"]:
        result["reasons"].append(f"URL resolution warning: {resolution['error']}")

    typo = looks_like_typosquat(hostname, KNOWN_BRANDS)
    result["typosquat"] = typo
    if typo.get("is_typosquat_suspected"):
        result["reasons"].append(
            f"Typosquatting suspected against {typo.get('matched_brand')} ({typo.get('reason')})"
        )

    try:
        gsb = check_google_safe_browsing(final_url)
        result["google_safe_browsing"] = gsb
        if gsb.get("matches"):
            threat_types = sorted({m.get("threatType", "UNKNOWN") for m in gsb["matches"]})
            result["reasons"].append(f"Google Safe Browsing match: {', '.join(threat_types)}")
    except requests.RequestException as e:
        result["google_safe_browsing"] = {"error": str(e)}
        result["reasons"].append(f"Google Safe Browsing error: {e}")

    # Whois Domain / Registration check
    whois_dom_res = check_whois_domain(hostname)
    result["whois_domain"] = whois_dom_res
    if whois_dom_res:
        if whois_dom_res.get("registered") is False:
            result["reasons"].append("Domain is completely unregistered or dead")
        age_days = whois_dom_res.get("age", {}).get("days")
        if age_days is not None and age_days < 30:
            result["reasons"].append(f"Domain is very new ({age_days} days old)")

    # SSL check
    ssl_res = check_whois_ssl(hostname)
    result["whois_ssl"] = ssl_res
    if ssl_res and not ssl_res.get("valid", True) and "disabled" not in ssl_res:
         result["reasons"].append("Domain has invalid or missing SSL certificate")

    gsb_matches = (result["google_safe_browsing"] or {}).get("matches", [])
    typo_flag = result["typosquat"]["is_typosquat_suspected"] if result["typosquat"] else False

    if gsb_matches:
        result["final_verdict"] = "UNSAFE"
    elif typo_flag:
        result["final_verdict"] = "SUSPICIOUS"
    else:
        result["final_verdict"] = "NO_KNOWN_THREAT_FOUND"

    return result


# ============================================================
# EMAIL PARSING HELPERS
# ============================================================

def parse_eml_file(filepath: str):
    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        content = f.read()

    raw_headers_match = re.search(
        r"=== FULL RAW HEADERS ===\n(.*?)\n=== BODY ===", content, re.DOTALL
    )
    body_match = re.search(r"=== BODY ===\n(.*)", content, re.DOTALL)

    raw_headers_text = raw_headers_match.group(1) if raw_headers_match else ""
    body_text = body_match.group(1) if body_match else ""

    raw_lines = raw_headers_text.strip().split("\n")
    if raw_lines and raw_lines[0].startswith("From "):
        raw_lines = raw_lines[1:]

    full_email = "\n".join(raw_lines) + "\n\n" + body_text
    return email_lib.message_from_string(full_email)


def is_image_url(url: str) -> bool:
    try:
        path = urlparse(url).path.lower()
        return any(path.endswith(ext) for ext in IMAGE_EXTENSIONS)
    except Exception:
        return False


def extract_urls_from_text(text: str) -> list[str]:
    urls = re.findall(r"https?://[^\s<>\"')\]]+(?<![.,;:!?])", text)
    return [u for u in urls if not is_image_url(u)]


class HrefExtractor(HTMLParser):
    def __init__(self):
        super().__init__()
        self.urls: list[str] = []

    def handle_starttag(self, _tag, attrs):
        for attr, value in attrs:
            if attr in ("href", "action") and value and value.startswith(("http://", "https://")):
                self.urls.append(value)


def extract_urls_from_html(html: str) -> list[str]:
    parser = HrefExtractor()
    try:
        parser.feed(html)
    except Exception:
        pass

    all_urls = parser.urls + extract_urls_from_text(html)
    seen = set()
    result = []
    for u in all_urls:
        if u not in seen and not is_image_url(u):
            seen.add(u)
            result.append(u)
    return result


def is_analysable_url(url: str) -> bool:
    if is_image_url(url):
        return False
    if re.search(r"/I\d+/", url):
        return False
    return True


def parse_auth_results(header_value: str) -> dict[str, str]:
    results = {}
    for mechanism in ("spf", "dkim", "dmarc", "iprev"):
        match = re.search(rf"\b{mechanism}=(\w+)", header_value, re.IGNORECASE)
        if match:
            results[mechanism] = match.group(1).lower()
    return results


def extract_domain_from_email_address(email_address: str) -> str:
    if "@" in email_address:
        return email_address.split("@")[-1].lower().strip()
    return ""


def extract_original_sender_from_body(plain_body: str) -> tuple[Optional[str], Optional[str]]:
    match = re.search(r"^From:\s*(.*?)<([^>]+)>", plain_body, re.IGNORECASE | re.MULTILINE)
    if match:
        original_from_header = f"{match.group(1).strip()} <{match.group(2).strip()}>".strip()
        original_email = match.group(2).strip()
        return original_from_header, original_email

    match = re.search(r"^From:\s*([^\s]+@[^\s]+)", plain_body, re.IGNORECASE | re.MULTILINE)
    if match:
        original_email = match.group(1).strip()
        return original_email, original_email

    return None, None


def extract_body_contact_emails(plain_body: str) -> list[str]:
    emails = re.findall(r'[\w\.-]+@[\w\.-]+\.\w+', plain_body)
    seen = set()
    result = []
    for e in emails:
        el = e.lower().strip()
        if el not in seen:
            seen.add(el)
            result.append(el)
    return result


# ============================================================
# CATEGORY / RISK
# ============================================================

def detect_category(subject: str, body_text: str, url_reports: list[dict[str, Any]]) -> Optional[str]:
    for url_report in url_reports:
        gsb = url_report.get("google_safe_browsing") or {}
        for match in gsb.get("matches", []):
            threat_type = match.get("threatType", "")
            if threat_type == "MALWARE":
                return "MALWARE"
            if threat_type == "SOCIAL_ENGINEERING":
                return "PHISHING"

    text = (subject + " " + body_text).lower()
    scores = {cat: 0 for cat in CATEGORY_KEYWORDS}

    for cat, keywords in CATEGORY_KEYWORDS.items():
        for kw in keywords:
            if kw in text:
                scores[cat] += 1

    best_cat, best_score = max(scores.items(), key=lambda x: x[1])
    return best_cat if best_score > 0 else None


def calculate_infrastructure_score(flags: list[str], url_reports: list[dict[str, Any]]) -> int:
    score = 0.0

    score += min(20, len(flags) * 10)

    for url_report in url_reports:
        gsb = url_report.get("google_safe_browsing") or {}
        if gsb.get("matches"):
            score += 50

        typo = url_report.get("typosquat") or {}
        if typo.get("is_typosquat_suspected"):
            score += 25
            score += min(10, typo.get("score", 0.0) * 10)

        if url_report.get("hops", 0) > 4:
            score += 10

        if url_report.get("resolution_error"):
            score += 20

        if url_report.get("whois_ssl", {}).get("valid") is False:
             score += 15
             
        whois_data = url_report.get("whois_domain", {})
        if whois_data.get("registered") is False:
             score += 30
        age_days = whois_data.get("age", {}).get("days")
        if age_days is not None and age_days < 30:
            score += 25

    return min(100, int(score))


def risk_label(score: int) -> str:
    if score >= 75:
        return "HIGH RISK"
    if score >= 50:
        return "MEDIUM RISK"
    if score >= 25:
        return "LOW RISK"
    return "LIKELY SAFE"


# ============================================================
# GEMINI
# ============================================================

def extract_brand_candidates(text: str, urls: list[str], effective_from_domain: str) -> list[str]:
    candidates = set()

    if effective_from_domain:
        candidates.add(effective_from_domain.lower())

    for url in urls:
        try:
            host = get_hostname(url)
            if host:
                candidates.add(host)
        except Exception:
            pass

    text_lower = text.lower()
    known_brand_terms = [
        "google", "microsoft", "apple", "amazon", "paypal", "github",
        "openai", "facebook", "instagram", "linkedin", "netflix",
        "dropbox", "outlook", "gmail", "barclays", "hsbc",
        "lloyds", "natwest", "royal mail", "dhl", "fedex", "ups",
        "xdp", "spaceship"
    ]

    for brand in known_brand_terms:
        if brand in text_lower:
            candidates.add(brand)

    return sorted(candidates)


def build_gemini_email_payload(report: dict[str, Any]) -> str:
    safe_url_summaries = []
    for u in report.get("url_reports", []):
        safe_url_summaries.append({
            "input_url": u.get("input_url"),
            "final_url": u.get("final_url"),
            "hostname": u.get("hostname"),
            "final_verdict": u.get("final_verdict"),
            "typosquat": u.get("typosquat"),
            "whois_domain": u.get("whois_domain", {}),
            "whois_ssl": u.get("whois_ssl", {}),
            "reasons": u.get("reasons", []),
        })

    payload = {
        "subject": report.get("subject", ""),
        "effective_from": report.get("effective_from", ""),
        "effective_from_domain": report.get("effective_from_domain", ""),
        "sender_source": report.get("sender_source", ""),
        "plain_body": report.get("plain_body", "")[:12000],
        "urls": report.get("urls_found", []),
        "url_reports": safe_url_summaries,
        "flags": report.get("flags", []),
        "ml_score": report.get("ml_score", 0),
        "heuristic_score": report.get("heuristic_score", 0),
        "infrastructure_score": report.get("infrastructure_score", 0),
        "candidate_brands": extract_brand_candidates(
            report.get("subject", "") + "\n" + report.get("plain_body", ""),
            report.get("urls_found", []),
            report.get("effective_from_domain", ""),
        ),
    }

    return json.dumps(payload, ensure_ascii=False, indent=2)


def analyze_with_gemini(report: dict[str, Any]) -> dict[str, Any]:
    if not GEMINI_API_KEY:
        return {"enabled": False, "error": "GEMINI_API_KEY not set"}

    client = genai.Client(api_key=GEMINI_API_KEY)

    prompt = f"""
You are an email scam analyst.

Return ONLY valid JSON.

Evaluate:
- whether this email is a scam
- scam probability from 0 to 100
- likely brand/entity mentioned
- whether that brand appears legitimate in this context
- scam type
- short explanation
- concrete red flags

Important rules:
- If this is a forwarded email, focus on the original sender/content, not the outer forwarding sender.
- Use content, URLs, sender domain, and extracted signals.
- Do not assume transport authentication means the message is legitimate.
- If no clear brand is present, brand_name should be null and brand_legitimate should be null.
- Do not treat third-party sending domains, tracking links, or service-provider subdomains as suspicious by themselves if URL resolution, Safe Browsing, and typosquatting checks do not indicate a threat.

Allowed scam_type values:
["PHISHING", "ADVANCE_FEE_SCAM", "DELIVERY_SCAM", "FINANCIAL_FRAUD", "JOB_SCAM", "MALWARE", "SPAM", "LEGITIMATE", "UNKNOWN"]

Email data:
{build_gemini_email_payload(report)}
""".strip()

    schema = {
        "type": "OBJECT",
        "properties": {
            "is_scam": {"type": "BOOLEAN"},
            "scam_probability": {"type": "INTEGER"},
            "brand_name": {"type": "STRING", "nullable": True},
            "brand_legitimate": {"type": "BOOLEAN", "nullable": True},
            "scam_type": {
                "type": "STRING",
                "enum": [
                    "PHISHING",
                    "ADVANCE_FEE_SCAM",
                    "DELIVERY_SCAM",
                    "FINANCIAL_FRAUD",
                    "JOB_SCAM",
                    "MALWARE",
                    "SPAM",
                    "LEGITIMATE",
                    "UNKNOWN"
                ]
            },
            "explanation": {"type": "STRING"},
            "red_flags": {
                "type": "ARRAY",
                "items": {"type": "STRING"}
            }
        },
        "required": [
            "is_scam",
            "scam_probability",
            "brand_name",
            "brand_legitimate",
            "scam_type",
            "explanation",
            "red_flags"
        ]
    }

    response = client.models.generate_content(
        model="gemini-2.5-flash-lite",
        contents=prompt,
        config={
            "response_mime_type": "application/json",
            "response_schema": schema,
            "temperature": 0.1,
        },
    )

    parsed = json.loads(response.text)
    parsed["enabled"] = True
    return parsed


# ============================================================
# EMAIL ANALYSIS
# ============================================================

def _analyze_email_msg(msg, model) -> dict[str, Any]:
    """Core analysis logic shared by analyze_email and analyze_email_raw."""
    top_from_header = msg.get("From", "")
    to_header = msg.get("To", "")
    
    from email.header import decode_header
    raw_sub = msg.get("Subject", "")
    subject = ""
    if raw_sub:
        for decoded_byte, charset in decode_header(raw_sub):
            if isinstance(decoded_byte, bytes):
                subject += decoded_byte.decode(charset or 'utf-8', errors='replace')
            else:
                subject += str(decoded_byte)
                
    date = msg.get("Date", "")
    reply_to = msg.get("Reply-To", "") or ""
    return_path = msg.get("Return-Path", "") or ""
    message_id = msg.get("Message-ID", "")

    top_from_match = re.search(r"<([^>]+)>", top_from_header)
    top_from_email = top_from_match.group(1).strip() if top_from_match else top_from_header.strip()
    top_from_domain = extract_domain_from_email_address(top_from_email)

    raw_urls: list[str] = []
    plain_body = ""

    for part in msg.walk():
        payload = part.get_payload(decode=True)
        if payload is None:
            continue

        charset = part.get_content_charset() or "utf-8"
        try:
            text = payload.decode(charset, errors="replace")
        except Exception:
            text = payload.decode("utf-8", errors="replace")

        content_type = part.get_content_type()
        if content_type == "text/plain":
            plain_body += text + "\n"
            raw_urls.extend(extract_urls_from_text(text))
        elif content_type == "text/html":
            raw_urls.extend(extract_urls_from_html(text))

    original_from_header, original_from_email = extract_original_sender_from_body(plain_body)

    if original_from_email:
        effective_from = original_from_header or original_from_email
        effective_from_email = original_from_email.lower().strip()
        effective_from_domain = extract_domain_from_email_address(effective_from_email)
        sender_source = "forwarded_original_sender"
    else:
        effective_from = top_from_header
        effective_from_email = top_from_email.lower().strip()
        effective_from_domain = top_from_domain
        sender_source = "top_level_sender"

    flags: list[str] = []

    reply_to_match = re.search(r"<([^>]+)>", reply_to)
    reply_to_email = reply_to_match.group(1).strip().lower() if reply_to_match else reply_to.strip().lower()
    if reply_to_email and effective_from_email and reply_to_email != effective_from_email:
        flags.append(f"Reply-To differs from effective sender: {reply_to_email} vs {effective_from_email}")

    rp_match = re.search(r"<([^>]+)>", return_path)
    rp_email = rp_match.group(1).strip().lower() if rp_match else return_path.strip().lower()
    if rp_email and effective_from_email and rp_email != effective_from_email:
        flags.append(f"Return-Path differs from effective sender: {rp_email} vs {effective_from_email}")

    body_contact_emails = extract_body_contact_emails(plain_body)
    for body_email in body_contact_emails:
        if (
            effective_from_email
            and body_email != effective_from_email
            and sender_source != "forwarded_original_sender"
        ):
            flags.append(f"Different contact email found in body: {body_email}")
            break

    seen = set()
    unique_urls = []
    for u in raw_urls:
        if u not in seen:
            seen.add(u)
            unique_urls.append(u)

    import concurrent.futures
    url_reports = []
    analyzable_urls = [u for u in unique_urls if is_analysable_url(u)]
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        future_to_url = {executor.submit(analyze_url, url): url for url in analyzable_urls[:15]}
        for future in concurrent.futures.as_completed(future_to_url):
            url = future_to_url[future]
            try:
                url_reports.append(future.result())
            except Exception as exc:
                url_reports.append({
                    "input_url": url,
                    "error": str(exc),
                    "final_verdict": "ERROR"
                })

    cleaned_body = clean_text(subject + " " + plain_body)
    ml_probability = float(model.predict_proba([cleaned_body])[0][1])
    ml_score = int(round(ml_probability * 100))

    heuristic_score = content_rule_score(subject + "\n" + plain_body)
    infrastructure_score = calculate_infrastructure_score(flags, url_reports)

    preliminary_score = int(round(
        (0.65 * ml_score) +
        (0.15 * infrastructure_score) +
        (0.20 * (heuristic_score / 30 * 100))
    ))

    preliminary_score = min(100, max(0, preliminary_score))
    scam_category = detect_category(subject, plain_body, url_reports)

    if scam_category in {"ADVANCE_FEE_SCAM", "PHISHING", "FINANCIAL_FRAUD"}:
        preliminary_score += 10
    preliminary_score = min(100, max(0, preliminary_score))

    gemini_result = {"enabled": False, "error": "Not run"}

    try:
        gemini_result = analyze_with_gemini({
            "subject": subject,
            "effective_from": effective_from,
            "effective_from_email": effective_from_email,
            "effective_from_domain": effective_from_domain,
            "sender_source": sender_source,
            "plain_body": plain_body,
            "urls_found": unique_urls,
            "url_reports": url_reports,
            "flags": flags,
            "ml_score": ml_score,
            "heuristic_score": heuristic_score,
            "infrastructure_score": infrastructure_score,
        })
    except Exception as exc:
        gemini_result = {
            "enabled": False,
            "error": f"Gemini analysis failed: {exc}"
        }

    final_score = preliminary_score
    gemini_score = None

    if gemini_result.get("enabled") and isinstance(gemini_result.get("scam_probability"), int):
        gemini_score = max(0, min(80, gemini_result["scam_probability"]))

        if infrastructure_score > 0 or flags:
            gemini_weight = 0.15
        else:
            gemini_weight = 0.10

        final_score = int(round(
            (0.55 * ml_score) +
            (0.15 * infrastructure_score) +
            (0.20 * (heuristic_score / 30 * 100)) +
            (gemini_weight * gemini_score)
        ))

        if sender_source == "forwarded_original_sender":
            final_score = int(final_score * 0.90)

        final_score = min(100, max(0, final_score))

    url_verdicts = [r.get("final_verdict", "UNKNOWN") for r in url_reports]

    if "UNSAFE" in url_verdicts or final_score >= 75:
        overall_verdict = "UNSAFE"
    elif "SUSPICIOUS" in url_verdicts or flags:
        overall_verdict = "SUSPICIOUS"
    elif final_score >= 50:
        overall_verdict = "SUSPICIOUS"
    elif final_score < 15 and all(v == "NO_KNOWN_THREAT_FOUND" for v in url_verdicts) and not flags:
        overall_verdict = "NO_KNOWN_THREAT_FOUND"
    else:
        overall_verdict = "UNKNOWN"

    reasons = []

    if ml_score >= 80:
        reasons.append(f"ML model strongly flagged scam-like language ({ml_score}/100)")
    elif ml_score >= 60:
        reasons.append(f"ML model found moderately suspicious language ({ml_score}/100)")

    if infrastructure_score >= 50:
        reasons.append(f"Infrastructure / URL risk is high ({infrastructure_score}/100)")
    elif infrastructure_score >= 20:
        reasons.append(f"Infrastructure / URL risk is moderate ({infrastructure_score}/100)")

    if heuristic_score >= 12:
        reasons.append(f"Content heuristics are strongly suspicious ({heuristic_score}/30)")
    elif heuristic_score >= 6:
        reasons.append(f"Content heuristics are moderately suspicious ({heuristic_score}/30)")

    reasons.extend(flags)

    for r in url_reports:
        for rr in r.get("reasons", []):
            reasons.append(rr)

    if gemini_result.get("enabled"):
        reasons.append(f"Gemini classified email as {gemini_result.get('scam_type')} ({gemini_result.get('scam_probability')}/100)")
        for flag in gemini_result.get("red_flags", []):
            reasons.append(f"Gemini red flag: {flag}")

    return {
        "top_from": top_from_header,
        "top_from_email": top_from_email,
        "top_from_domain": top_from_domain,
        "effective_from": effective_from,
        "effective_from_email": effective_from_email,
        "effective_from_domain": effective_from_domain,
        "sender_source": sender_source,
        "to": to_header,
        "subject": subject,
        "date": date,
        "reply_to": reply_to,
        "return_path": return_path,
        "message_id": message_id,
        "flags": flags,
        "urls_found": unique_urls,
        "url_reports": url_reports,
        "plain_body": plain_body,
        "ml_probability": ml_probability,
        "ml_score": ml_score,
        "heuristic_score": heuristic_score,
        "infrastructure_score": infrastructure_score,
        "scam_probability": final_score,
        "scam_category": scam_category,
        "overall_verdict": overall_verdict,
        "risk_label": risk_label(final_score),
        "reasons": reasons,
        "gemini": gemini_result,
        "brand_name": gemini_result.get("brand_name"),
        "brand_legitimate": gemini_result.get("brand_legitimate"),
        "gemini_scam_type": gemini_result.get("scam_type"),
        "gemini_score": gemini_result.get("scam_probability"),
    }


def analyze_email_raw(raw_email: str, model) -> dict[str, Any]:
    """Analyze a raw RFC 2822 email string (used by the API)."""
    msg = email_lib.message_from_string(raw_email)
    return _analyze_email_msg(msg, model)


def analyze_email(filepath: str, model) -> dict[str, Any]:
    msg = parse_eml_file(filepath)
    return _analyze_email_msg(msg, model)


# ============================================================
# OUTPUT
# ============================================================

def print_url_report(report: dict[str, Any]) -> None:
    print("-" * 80)
    print("Input URL  :", report.get("input_url"))
    print("Final URL  :", report.get("final_url"))
    print("Host       :", report.get("hostname"))
    print("Resolution :", report.get("resolution_method"), f"({report.get('hops', 0)} hop(s))")
    if report.get("resolution_error"):
        print("Res. Error :", report["resolution_error"])

    typo = report.get("typosquat") or {}
    if typo:
        print("Typosquat  :", typo.get("is_typosquat_suspected"))
        print("Brand      :", typo.get("matched_brand"))
        print("Why        :", typo.get("reason"))

    gsb = report.get("google_safe_browsing") or {}
    if gsb.get("matches"):
        print("GSB        : MATCH")
    elif gsb.get("disabled"):
        print("GSB        : DISABLED")
    elif gsb.get("error"):
        print("GSB        : ERROR")

    print("Verdict    :", report.get("final_verdict"))

    if report.get("reasons"):
        print("Reasons:")
        for reason in report["reasons"]:
            print(" -", reason)


def print_email_report(report: dict[str, Any]) -> None:
    print("=" * 80)
    print("EMAIL ANALYSIS REPORT")
    print("=" * 80)
    print(f"Top-Level From      : {report['top_from']}")
    print(f"Effective Sender    : {report['effective_from']}")
    print(f"Effective Domain    : {report['effective_from_domain']}")
    print(f"Sender Source       : {report['sender_source']}")
    print(f"To                  : {report['to']}")
    print(f"Subject             : {report['subject']}")
    print(f"Date                : {report['date']}")
    if report["reply_to"]:
        print(f"Reply-To            : {report['reply_to']}")
    if report["return_path"]:
        print(f"Return-Path         : {report['return_path']}")
    print()

    print("[Model Scores]")
    print(f"  ML Score              : {report['ml_score']}/100")
    print(f"  Heuristic Score       : {report['heuristic_score']}/30")
    print(f"  Infrastructure Score  : {report['infrastructure_score']}/100")
    print()

    print("[Flags]")
    if report["flags"]:
        for flag in report["flags"]:
            print(" -", flag)
    else:
        print("  None")
    print()

    print(f"[URLs Found — {len(report['urls_found'])}]")
    for url in report["urls_found"]:
        print(" ", url)
    print()

    if report["url_reports"]:
        print("[URL Analysis]")
        for url_report in report["url_reports"]:
            if url_report.get("final_verdict") == "ERROR":
                print(f"  ERROR: {url_report['input_url']} — {url_report.get('error')}")
            else:
                print_url_report(url_report)
        print()

    print("[Gemini Analysis]")
    gemini = report.get("gemini", {})
    if gemini.get("enabled"):
        print(f"  Gemini Score         : {gemini.get('scam_probability')}/100")
        print(f"  Is Scam              : {gemini.get('is_scam')}")
        print(f"  Brand Name           : {gemini.get('brand_name')}")
        print(f"  Brand Legitimate     : {gemini.get('brand_legitimate')}")
        print(f"  Scam Type            : {gemini.get('scam_type')}")
        print(f"  Explanation          : {gemini.get('explanation')}")
        if gemini.get("red_flags"):
            print("  Red Flags:")
            for flag in gemini["red_flags"]:
                print("   -", flag)
    else:
        print(f"  Gemini unavailable   : {gemini.get('error', 'Not run')}")
    print()

    print("[Final Result]")
    print(f"  Overall Verdict   : {report['overall_verdict']}")
    print(f"  Scam Probability  : {report['scam_probability']}/100")
    print(f"  Risk Level        : {report['risk_label']}")

    if report.get("gemini_scam_type"):
        print(f"  Category   : {report['gemini_scam_type']}")
    if report.get("brand_name") is not None:
        print(f"  Brand             : {report['brand_name']}")
        print(f"  Brand Legitimate  : {report['brand_legitimate']}")
    print()

    print("[Reasons]")
    if report["reasons"]:
        for reason in report["reasons"]:
            print(" -", reason)
    else:
        print("  None")

    print("=" * 80)


def save_report_json(report: dict[str, Any], output_path: str) -> None:
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    print(f"Saved report JSON to {output_path}")


# ============================================================
# CLI
# ============================================================

def usage() -> None:
    print(
        "\nUsage:\n"
        "  python main.py train\n"
        "      Train TF-IDF + Logistic Regression model from phishing_email.csv\n\n"
        "  python main.py analyze sample_email.eml\n"
        "      Analyze one saved email file using the trained hybrid model\n\n"
        "  python main.py analyze sample_email.eml report.json\n"
        "      Analyze email and also save JSON report\n"
    )


# ============================================================
# FASTAPI APP
# ============================================================

app = FastAPI()

try:
    api_model = load_model()
except Exception:
    api_model = None

@app.post("/analyze")
async def analyze_endpoint(request: Request):
    if api_model is None:
        raise HTTPException(status_code=500, detail="Model not loaded or trained. Run 'python main.py train' first.")

    raw_body = await request.body()
    raw_email = raw_body.decode("utf-8", errors="replace")

    report = analyze_email_raw(raw_email, api_model)

    effective_from_email = report.get("effective_from_email")
    top_from_email = report.get("top_from_email")
    
    if not top_from_email:
        return {"status": "skipped", "reason": "No top_from_email extracted", "report": report}

    # Query Database
    try:
        with psycopg.connect(DATABASE_URL, row_factory=dict_row) as conn:
            with conn.cursor() as cur:
                # Check user exists
                cur.execute(
                    "SELECT id FROM users WHERE lower(email) = lower(%s)",
                    (top_from_email,)
                )
                user = cur.fetchone()

                if not user:
                    return {"status": "skipped", "reason": f"User {top_from_email} not found"}

                user_id = user["id"]
                message_id = report.get("message_id")
                if not message_id:
                    message_id = str(uuid.uuid4())

                # Parse date
                received_at = None
                date_str = report.get("date")
                if date_str:
                    try:
                        received_at = parsedate_to_datetime(date_str)
                    except Exception:
                        pass
                
                now = datetime.now(timezone.utc)

                insert_query = """
                    INSERT INTO email_submissions (
                        user_id, message_id, subject, top_from, top_from_email,
                        effective_from, effective_from_email, effective_from_domain,
                        sender_source, received_at, overall_verdict, risk_label,
                        scam_probability, scam_category, ml_score, heuristic_score,
                        infrastructure_score, gemini_score, gemini_scam_type,
                        brand_name, brand_legitimate, flags, reasons, urls_found,
                        url_reports, analysis_json, raw_email, created_at, updated_at
                    ) VALUES (
                        %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                        %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                        %s, %s, %s, %s, %s, %s, %s, %s, %s
                    ) ON CONFLICT (user_id, message_id) DO NOTHING
                """
                
                analysis_json = json.dumps(report)
                flags_json = json.dumps(report.get("flags", []))
                reasons_json = json.dumps(report.get("reasons", []))
                urls_found_json = json.dumps(report.get("urls_found", []))
                url_reports_json = json.dumps(report.get("url_reports", []))

                cur.execute(insert_query, (
                    user_id,
                    message_id,
                    report.get("subject"),
                    report.get("top_from"),
                    report.get("top_from_email"),
                    report.get("effective_from"),
                    report.get("effective_from_email"),
                    report.get("effective_from_domain"),
                    report.get("sender_source"),
                    received_at,
                    report.get("overall_verdict"),
                    report.get("risk_label"),
                    report.get("scam_probability"),
                    report.get("scam_category"),
                    report.get("ml_score"),
                    report.get("heuristic_score"),
                    report.get("infrastructure_score"),
                    report.get("gemini_score"),
                    report.get("gemini_scam_type"),
                    report.get("brand_name"),
                    report.get("brand_legitimate"),
                    flags_json,
                    reasons_json,
                    urls_found_json,
                    url_reports_json,
                    analysis_json,
                    raw_email,
                    now,
                    now
                ))
            conn.commit()
            
        return {"status": "success", "user_id": user_id, "message_id": message_id}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


def main():
    if len(sys.argv) < 2:
        usage()
        return

    command = sys.argv[1].lower()

    if command == "train":
        train_model()
        return

    if command == "analyze":
        if len(sys.argv) < 3:
            usage()
            return

        email_file = sys.argv[2]
        json_out = sys.argv[3] if len(sys.argv) >= 4 else None

        model = load_model()
        report = analyze_email(email_file, model)
        print_email_report(report)

        if json_out:
            save_report_json(report, json_out)
        return

    usage()


if __name__ == "__main__":
    main()
