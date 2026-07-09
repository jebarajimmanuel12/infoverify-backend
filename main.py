from fastapi import FastAPI, HTTPException, Header, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, List
from textblob import TextBlob
import urllib.parse
import re
import datetime

app = FastAPI(title="InfoVerify Enterprise Engine", version="9.3.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], 
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- IN-MEMORY DATABASE (Swap with SQLite/MongoDB later) ---
fake_db = {
    "Jrajimman12": {"pwd": "admin", "role": "dev", "history": []},
    "m416johnson": {"pwd": "password123", "role": "user", "history": []}
}

# --- SCHEMAS ---
class LoginPayload(BaseModel):
    username: str
    password: str

class ResetPayload(BaseModel):
    target_username: str
    new_password: str

class Payload(BaseModel):
    url: str
    headline: str
    username: str # To track who made the request

# --- TRUST DATABASES ---
TLD_WEIGHTS = { 
    '.gov': 50, '.mil': 50, '.edu': 45, '.bank': 45, '.int': 45, '.ac.in': 45,
    '.com': 0, '.org': 10, '.net': 0, '.io': 5,
    '.xyz': -20, '.click': -40, '.onion': -50, '.tk': -45
}
TRUSTED_DOMAINS = ['bbc.com', 'reuters.com', 'apnews.com', 'npr.org', 'drmgrdu.ac.in', 'nature.com']
URL_SHORTENERS = ['bit.ly', 'tinyurl.com', 't.co']
CLICKBAIT_PHRASES = ["you won't believe", "shocking", "this one trick", "what happens next", "secret"]

def extract_domain_info(url_string: str):
    try:
        parsed = urllib.parse.urlparse(url_string if "://" in url_string else "http://" + url_string)
        hostname = parsed.hostname.lower().replace("www.", "")
        parts = hostname.split('.')
        tld = "." + ".".join(parts[-2:]) if len(parts) > 2 and len(parts[-2]) <= 3 else "." + parts[-1]
        return hostname, tld
    except:
        return "", ""

# --- AUTH ENDPOINTS ---
@app.post("/api/v1/auth/login")
async def login(payload: LoginPayload):
    user = fake_db.get(payload.username)
    if not user or user["pwd"] != payload.password:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    return {
        "success": True, 
        "username": payload.username, 
        "role": user["role"],
        "history": user["history"]
    }

@app.post("/api/v1/auth/reset")
async def reset_password(payload: ResetPayload, username: str = Header(None)):
    requester = fake_db.get(username)
    if not requester or requester["role"] != "dev":
        raise HTTPException(status_code=403, detail="Only developers can reset passwords.")
    
    target = fake_db.get(payload.target_username)
    if not target:
        raise HTTPException(status_code=404, detail="User not found.")
    
    target["pwd"] = payload.new_password
    return {"success": True, "message": f"Password updated for {payload.target_username}"}

# --- ENGINE ENDPOINTS ---
@app.post("/api/v1/analyze")
async def analyze(payload: Payload):
    headline = payload.headline.strip()
    url = payload.url.lower().strip()
    lower_head = headline.lower()
    
    if payload.username not in fake_db:
        raise HTTPException(status_code=401, detail="Unauthorized user")

    source_score, ling_score, form_score = 50, 75, 90
    audit_log = []
    
    if url:
        hostname, tld = extract_domain_info(url)
        if url.startswith("http://"):
            source_score -= 40
            audit_log.append({"type": "negative", "text": "Website is not secure (uses HTTP)."})

        weight = TLD_WEIGHTS.get(tld, 0)
        source_score += weight
        
        if any(hostname.endswith(t) for t in TRUSTED_DOMAINS):
            source_score = 95
            audit_log.append({"type": "positive", "text": "Verified official news source."})
        elif any(hostname.endswith(u) for u in URL_SHORTENERS):
            source_score = 20
            audit_log.append({"type": "negative", "text": "Link is hidden behind a shortener."})

    found_clickbait = [p for p in CLICKBAIT_PHRASES if p in lower_head]
    if found_clickbait:
        ling_score -= (20 * len(found_clickbait))
        audit_log.append({"type": "negative", "text": f"Clickbait words found: '{found_clickbait[0]}'"})

    analysis = TextBlob(headline)
    if analysis.sentiment.subjectivity > 0.6:
        ling_score -= 25
    elif analysis.sentiment.subjectivity < 0.3:
        ling_score += 15

    if re.search(r'(!!+|\?\?+|\?!|!\?)', headline):
        form_score -= 25
        audit_log.append({"type": "negative", "text": "Unprofessional punctuation detected."})

    source_score = max(5, min(98, source_score))
    ling_score = max(5, min(98, ling_score))
    form_score = max(5, min(98, form_score))
    final_score = int((source_score * 0.45) + (ling_score * 0.35) + (form_score * 0.20))

    # Save to user history
    record = {
        "url": url, 
        "head": headline, 
        "score": final_score, 
        "date": datetime.datetime.now().strftime("%I:%M %p")
    }
    fake_db[payload.username]["history"].insert(0, record)
    fake_db[payload.username]["history"] = fake_db[payload.username]["history"][:5] # Keep last 5

    return {
        "validData": True, "finalTrustScore": final_score, 
        "sourceScore": source_score, "lingScore": ling_score, "formScore": form_score, 
        "auditLog": audit_log,
        "newHistory": fake_db[payload.username]["history"]
    }