from fastapi import FastAPI, HTTPException, Header
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import urllib.parse
import re
import datetime
from textblob import TextBlob

app = FastAPI(title="InfoVerify Enterprise Engine", version="11.0.0")

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

# --- ENGINE HELPERS ---
TLD_WEIGHTS = { 
    '.gov': 50, '.mil': 50, '.edu': 45, '.bank': 45, '.int': 45, '.ac.in': 45,
    '.com': 0, '.org': 10, '.net': 0, '.io': 5,
    '.xyz': -20, '.click': -40, '.onion': -50, '.tk': -45
}
TRUSTED_DOMAINS = ['bbc.com', 'reuters.com', 'apnews.com', 'npr.org', 'drmgrdu.ac.in', 'nature.com']
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

    # Migrate data to new key if username changed
    user_data = fake_db.pop(username)
    user_data["pwd"] = payload.new_password
    fake_db[payload.new_username] = user_data
    
    return {"success": True, "message": "Profile updated", "new_username": payload.new_username}

# --- ADMIN MANAGEMENT ENDPOINTS ---
@app.get("/api/v1/admin/users")
async def get_all_users(username: str = Header(None)):
    req = fake_db.get(username)
    if not req or req["role"] != "dev": raise HTTPException(status_code=403, detail="Admin only.")
    
    # Return user list without exposing passwords securely to the frontend
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

# --- ENGINE ENDPOINTS ---
@app.post("/api/v1/analyze")
async def analyze(payload: Payload):
    headline = payload.headline.strip()
    url = payload.url.lower().strip()
    if payload.username not in fake_db: raise HTTPException(status_code=401, detail="Unauthorized user")

    source_score, ling_score, form_score = 50, 75, 90
    audit_log = []
    
    if url:
        hostname, tld = extract_domain_info(url)
        if url.startswith("http://"):
            source_score -= 40
            audit_log.append({"type": "negative", "text": "Website uses HTTP instead of HTTPS."})
        source_score += TLD_WEIGHTS.get(tld, 0)
        if any(hostname.endswith(t) for t in TRUSTED_DOMAINS): source_score = 95

    if any(p in headline.lower() for p in CLICKBAIT_PHRASES): ling_score -= 20
    
    analysis = TextBlob(headline)
    if analysis.sentiment.subjectivity > 0.6: ling_score -= 25
    elif analysis.sentiment.subjectivity < 0.3: ling_score += 15

    if re.search(r'(!!+|\?\?+|\?!|!\?)', headline): form_score -= 25

    final_score = int((max(5, min(98, source_score)) * 0.45) + (max(5, min(98, ling_score)) * 0.35) + (max(5, min(98, form_score)) * 0.20))

    record = {"url": url, "head": headline, "score": final_score, "date": datetime.datetime.now().strftime("%I:%M %p")}
    fake_db[payload.username]["history"].insert(0, record)
    fake_db[payload.username]["history"] = fake_db[payload.username]["history"][:5]

    return {
        "validData": True, "finalTrustScore": final_score, 
        "sourceScore": max(5, min(98, source_score)), "lingScore": max(5, min(98, ling_score)), "formScore": max(5, min(98, form_score)), 
        "auditLog": audit_log, "newHistory": fake_db[payload.username]["history"]
    }

@app.get("/")
async def serve_frontend():
    return FileResponse("index.html")
