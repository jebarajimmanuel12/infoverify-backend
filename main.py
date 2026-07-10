from fastapi import FastAPI, HTTPException, Header
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import urllib.parse
import re
import datetime
import httpx
from textblob import TextBlob

app = FastAPI(title="InfoVerify Enterprise Engine", version="12.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], 
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- IN-MEMORY DATABASE ---
fake_db = {
    "Jrajimman12": {"pwd": "admin", "role": "dev", "history": []},
    "m416johnson": {"pwd": "password123", "role": "user", "history": []}
}

# --- SCHEMAS ---
class AuthPayload(BaseModel):
    username: str
    password: str

class UpdateSelfPayload(BaseModel):
    new_username: str
    new_password: str

class AdminCreatePayload(BaseModel):
    new_username: str
    new_password: str
    role: str

class AdminEditPayload(BaseModel):
    old_username: str
    new_username: str
    new_password: str

class Payload(BaseModel):
    url: str
    headline: str
    username: str

# --- ENGINE HELPERS & LIVE API CONFIG ---
TLD_WEIGHTS = { 
    '.gov': 50, '.mil': 50, '.edu': 45, '.bank': 45, '.int': 45, '.ac.in': 45,
    '.com': 0, '.org': 10, '.net': 0, '.io': 5,
    '.xyz': -20, '.click': -40, '.onion': -50, '.tk': -45
}
TRUSTED_DOMAINS = ['bbc.com', 'reuters.com', 'apnews.com', 'npr.org', 'drmgrdu.ac.in', 'nature.com', 'bloomberg.com', 'wsj.com', 'nytimes.com']
CLICKBAIT_PHRASES = ["you won't believe", "shocking", "this one trick", "what happens next", "secret", "mind blowing", "is this the end"]

# Real-time tracking for heavy global impact vectors
GLOBAL_CRISIS_KEYWORDS = [
    "war", "conflict", "invasion", "military", "missile", "shelling", 
    "famine", "starvation", "drought", "humanitarian aid",
    "tariff", "trade war", "sanction", "embargo", "recession", "gdp", "pandemic"
]

# External News API Config (Using newsapi.org blueprint - replace with your live key on Render via Env Vars)
NEWS_API_URL = "https://newsapi.org/v2/everything"
NEWS_API_KEY = "YOUR_LIVE_NEWS_API_KEY"

def extract_domain_info(url_string: str):
    try:
        if not url_string:
            return "", ""
        parsed = urllib.parse.urlparse(url_string if "://" in url_string else "http://" + url_string)
        hostname = parsed.hostname.lower().replace("www.", "")
        parts = hostname.split('.')
        tld = "." + ".".join(parts[-2:]) if len(parts) > 2 and len(parts[-2]) <= 3 else "." + parts[-1]
        return hostname, tld
    except:
        return "", ""

async def check_live_global_coverage(headline: str) -> tuple[int, list]:
    """
    Scans the headline for critical global events and queries an external news feed.
    """
    detected_keywords = [word for word in GLOBAL_CRISIS_KEYWORDS if word in headline.lower()]
    if not detected_keywords:
        return 0, []

    logs = [{"type": "warning", "text": f"Global impact topic detected: {', '.join(detected_keywords)}. Cross-referencing live databases..."}]
    
    search_query = " AND ".join(detected_keywords[:2])
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                NEWS_API_URL,
                params={
                    "q": search_query,
                    "sortBy": "relevancy",
                    "pageSize": 5,
                    "apiKey": NEWS_API_KEY
                },
                timeout=3.0
            )
            
            if response.status_code == 200:
                data = response.json()
                total_results = data.get("totalResults", 0)
                
                if total_results >= 10:
                    logs.append({"type": "positive", "text": "Active global news coverage confirms this topic is currently trending across major networks."})
                    return 15, logs 
                elif total_results > 0:
                    logs.append({"type": "warning", "text": f"Minor real-time coverage found ({total_results} matching items). Situation may be developing."})
                    return 5, logs
                else:
                    logs.append({"type": "negative", "text": "Warning: High-impact claim detected, but zero live matching coverage found from trusted sources. Likely false."})
                    return -30, logs 
            else:
                logs.append({"type": "warning", "text": "Live news verification service is temporarily unavailable. Proceeding with standard static analysis."})
                return 0, logs
    except Exception:
        logs.append({"type": "warning", "text": "Network timeout while checking global news feeds. Proceeding with standard static analysis."})
        return 0, logs


# --- AUTH ENDPOINTS ---
@app.post("/api/v1/auth/login")
async def login(payload: AuthPayload):
    user = fake_db.get(payload.username)
    if not user or user["pwd"] != payload.password:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    return {"success": True, "username": payload.username, "role": user["role"], "history": user["history"]}

@app.post("/api/v1/auth/register")
async def register(payload: AuthPayload):
    if payload.username in fake_db:
        raise HTTPException(status_code=400, detail="Username already exists")
    fake_db[payload.username] = {"pwd": payload.password, "role": "user", "history": []}
    return {"success": True, "username": payload.username, "role": "user", "history": []}

# --- USER PROFILE ENDPOINTS ---
@app.put("/api/v1/users/me")
async def edit_my_profile(payload: UpdateSelfPayload, username: str = Header(None)):
    user = fake_db.get(username)
    if not user: raise HTTPException(status_code=401, detail="Unauthorized")
    
    if payload.new_username != username and payload.new_username in fake_db:
        raise HTTPException(status_code=400, detail="Username already taken.")

    user_data = fake_db.pop(username)
    user_data["pwd"] = payload.new_password
    fake_db[payload.new_username] = user_data
    
    return {"success": True, "message": "Profile updated", "new_username": payload.new_username}

# --- ADMIN MANAGEMENT ENDPOINTS ---
@app.get("/api/v1/admin/users")
async def get_all_users(username: str = Header(None)):
    req = fake_db.get(username)
    if not req or req["role"] != "dev": raise HTTPException(status_code=403, detail="Admin only.")
    
    users = [{"username": k, "role": v["role"], "pwd": v["pwd"]} for k, v in fake_db.items()]
    return {"success": True, "users": users}

@app.post("/api/v1/admin/create_user")
async def create_user(payload: AdminCreatePayload, username: str = Header(None)):
    req = fake_db.get(username)
    if not req or req["role"] != "dev": raise HTTPException(status_code=403, detail="Admin only.")
    
    if payload.new_username in fake_db:
        raise HTTPException(status_code=400, detail="Username already exists.")
    
    fake_db[payload.new_username] = {"pwd": payload.new_password, "role": payload.role, "history": []}
    return {"success": True, "message": f"Account '{payload.new_username}' created."}

@app.put("/api/v1/admin/edit_user")
async def edit_user(payload: AdminEditPayload, username: str = Header(None)):
    req = fake_db.get(username)
    if not req or req["role"] != "dev": raise HTTPException(status_code=403, detail="Admin only.")
    
    target = fake_db.get(payload.old_username)
    if not target: raise HTTPException(status_code=404, detail="User not found.")
    
    if payload.new_username != payload.old_username and payload.new_username in fake_db:
        raise HTTPException(status_code=400, detail="New username already taken.")

    target_data = fake_db.pop(payload.old_username)
    target_data["pwd"] = payload.new_password
    fake_db[payload.new_username] = target_data
    
    return {"success": True, "message": "User updated successfully."}


# --- ENGINE ANALYSIS ENDPOINT ---
@app.post("/api/v1/analyze")
async def analyze(payload: Payload):
    headline = payload.headline.strip()
    url = payload.url.lower().strip() if payload.url else ""
    if payload.username not in fake_db: raise HTTPException(status_code=401, detail="Unauthorized user")

    source_score, ling_score, form_score = 50, 75, 90
    audit_log = []
    
    # 1. Source Domain Evaluation
    if url:
        hostname, tld = extract_domain_info(url)
        if url.startswith("http://"):
            source_score -= 40
            audit_log.append({"type": "negative", "text": "Website uses insecure HTTP instead of encrypted HTTPS."})
        
        source_score += TLD_WEIGHTS.get(tld, 0)
        
        if any(hostname.endswith(t) for t in TRUSTED_DOMAINS): 
            source_score = 95
            audit_log.append({"type": "positive", "text": f"Domain identified within our heavily trusted global network ({hostname})."})
        elif TLD_WEIGHTS.get(tld, 0) < 0:
            audit_log.append({"type": "warning", "text": f"Suspicious Top-Level Domain detected ({tld}). Usually associated with spam."})
    else:
        audit_log.append({"type": "warning", "text": "No source URL provided. Analysis relying solely on NLP and linguistic structure."})

    # 2. Linguistic Integrity Analysis
    if any(p in headline.lower() for p in CLICKBAIT_PHRASES): 
        ling_score -= 20
        audit_log.append({"type": "negative", "text": "Headline patterns contain recognized sensationalist/clickbait phrases."})
        
    analysis = TextBlob(headline)
    if analysis.sentiment.subjectivity > 0.6: 
        ling_score -= 25
        audit_log.append({"type": "negative", "text": "Linguistic tone flags high personal bias or subjective opinion."})
    elif analysis.sentiment.subjectivity < 0.3: 
        ling_score += 15
        audit_log.append({"type": "positive", "text": "Text maintains a neutral, highly objective reporting tone."})

    # 3. Structural Formatting Evaluation
    if re.search(r'(!!+|\?\?+|\?!|!\?)', headline): 
        form_score -= 25
        audit_log.append({"type": "negative", "text": "Exaggerated punctuation detected (e.g., !! or ??)."})
    if headline.isupper():
        form_score -= 30
        audit_log.append({"type": "negative", "text": "Headline is written entirely in uppercase (ALL CAPS). Highly unprofessional."})

    # 4. Live News Verification Layer (Async)
    live_score_modifier, live_logs = await check_live_global_coverage(headline)
    audit_log.extend(live_logs)

    # Normalize localized matrix calculations to fit within 5-98 bounds
    norm_source = max(5, min(98, source_score))
    norm_ling = max(5, min(98, ling_score))
    norm_form = max(5, min(98, form_score))

    # Incorporate the live context score modifier directly into the core calculations
    calculated_score = int((norm_source * 0.40) + (norm_ling * 0.35) + (norm_form * 0.25)) + live_score_modifier
    final_score = max(5, min(98, calculated_score))

    record = {"url": url, "head": headline, "score": final_score, "date": datetime.datetime.now().strftime("%I:%M %p")}
    
    # Store history
    fake_db[payload.username]["history"].insert(0, record)
    fake_db[payload.username]["history"] = fake_db[payload.username]["history"][:5]

    return {
        "validData": True, 
        "finalTrustScore": final_score, 
        "sourceScore": norm_source, 
        "lingScore": norm_ling, 
        "formScore": norm_form, 
        "auditLog": audit_log, 
        "newHistory": fake_db[payload.username]["history"]
    }

# --- SERVE FRONTEND ---
@app.get("/")
async def serve_frontend():
    return FileResponse("index.html")
