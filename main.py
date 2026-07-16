from fastapi import FastAPI, HTTPException, Header
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import urllib.parse
import re
import time
import difflib
import datetime
import httpx
from textblob import TextBlob

app = FastAPI(title="InfoVerify Enterprise Engine", version="14.0.0")
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
    "m416johnson": {"pwd": "Johnson@2006", "role": "dev", "history": []},
    "abdur1905": {"pwd": "iamuruttu", "role": "dev", "history": []},
    "laxmijohnson": {"pwd": "laxmi2627johnson", "role": "dev", "history": []},
    "varunsampath": {"pwd": "Rajalohar", "role": "user", "history": []},
    "sasitravels": {"pwd": "sttravels@tn69", "role": "user", "history": []}
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

# =====================================================================
# ENGINE CONFIG - this is the part that got the real upgrade
# =====================================================================

TLD_WEIGHTS = {
    '.gov': 50, '.gov.in': 50, '.mil': 50, '.edu': 45, '.ac.in': 45, '.bank': 45,
    '.int': 45, '.nic.in': 40, '.org': 10, '.coop': 8,
    '.com': 0, '.net': 0, '.io': 5, '.co': 0, '.news': 5, '.press': 5, '.info': -5,
    '.xyz': -20, '.top': -25, '.click': -40, '.link': -35, '.tk': -45,
    '.ml': -45, '.ga': -45, '.cf': -45, '.gq': -45, '.onion': -50,
}

TRUSTED_DOMAINS = [
    # Global wire services & major outlets
    'bbc.com', 'reuters.com', 'apnews.com', 'npr.org', 'nature.com',
    'bloomberg.com', 'wsj.com', 'nytimes.com', 'theguardian.com',
    'economist.com', 'aljazeera.com', 'dw.com',
    # Indian national outlets
    'thehindu.com', 'indianexpress.com', 'ndtv.com', 'hindustantimes.com',
    'timesofindia.indiatimes.com', 'livemint.com', 'thewire.in', 'pib.gov.in',
    # Educational
    'drmgrdu.ac.in',
    # Fact-checking bodies - a headline sourced FROM these is a good sign,
    # not a bad one, since their entire job is verification.
    'altnews.in', 'factcheck.org', 'snopes.com', 'politifact.com', 'boomlive.in',
]

# Phrases that exist purely to bait a click rather than inform.
CLICKBAIT_PHRASES = [
    "you won't believe", "shocking", "this one trick", "what happens next",
    "secret", "mind blowing", "is this the end", "will leave you speechless",
    "doctors hate", "gone wrong", "gone viral", "broke the internet",
    "changed everything", "number 5 will", "you'll never guess",
]

# "7 reasons why...", "10 things nobody tells you..." - classic listicle bait.
LISTICLE_PATTERN = re.compile(r'^\s*\d{1,3}\s+(reasons|ways|things|facts|tips|secrets|signs|times)\b', re.IGNORECASE)

# Absolutist / unfalsifiable language often used to oversell a claim.
ABSOLUTE_CLAIM_WORDS = [
    "always", "never", "guaranteed", "proven", "100%", "completely",
    "totally", "undeniable", "irrefutable", "everyone knows", "no one tells you",
]

# Attribution to nobody in particular - a red flag for unverifiable claims.
UNVERIFIED_ATTRIBUTION_PHRASES = [
    "sources say", "many believe", "some say", "rumor has it", "it is said",
    "insiders claim", "experts warn", "people are saying", "reportedly",
]

# Attribution to somebody specific ("according to Reuters") is a *good* sign -
# it means the claim is traceable back to a named source.
NAMED_ATTRIBUTION_PATTERN = re.compile(r'\baccording to\s+([A-Z][A-Za-z.&]+)', re.UNICODE)

EMOJI_PATTERN = re.compile(
    "["
    "\U0001F300-\U0001FAFF"
    "\U00002600-\U000027BF"
    "\U0001F1E6-\U0001F1FF"
    "]+", flags=re.UNICODE
)

# Real-time tracking for heavy global impact vectors
GLOBAL_CRISIS_KEYWORDS = [
    "war", "conflict", "invasion", "military", "missile", "shelling",
    "famine", "starvation", "drought", "humanitarian aid",
    "tariff", "trade war", "sanction", "embargo", "recession", "gdp", "pandemic"
]

# External News API Config (Using newsapi.org blueprint - replace with your live key on Render via Env Vars)
NEWS_API_URL = "https://newsapi.org/v2/everything"
NEWS_API_KEY = "YOUR_LIVE_NEWS_API_KEY"

# Tiny in-memory cache so repeated/similar headlines during a demo don't
# burn through the News API's free-tier rate limit.
_NEWS_CACHE: dict = {}
_NEWS_CACHE_TTL_SECONDS = 300


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


def check_typosquatting(hostname: str):
    """
    Flags domains that are suspiciously close to a trusted domain without
    being an exact match - e.g. 'bbc-news-online.com' or 'reuter.com'
    impersonating 'bbc.com' / 'reuters.com'. Catches misinformation sites
    that deliberately mimic a trusted brand's URL.
    """
    if not hostname:
        return None
    for trusted in TRUSTED_DOMAINS:
        if hostname == trusted:
            return None  # exact match, not a spoof
        similarity = difflib.SequenceMatcher(None, hostname, trusted).ratio()
        if similarity >= 0.80:
            return trusted
    return None


def analyze_claim_language(headline: str):
    """
    Looks at *how* a claim is being made rather than what topic it's on:
    absolutist wording, vague crowd-sourced attribution, or listicle bait
    all tend to correlate with lower-quality reporting. Naming a specific,
    checkable source is treated as a positive signal.
    """
    score = 0
    logs = []
    lower = headline.lower()

    absolute_hits = [w for w in ABSOLUTE_CLAIM_WORDS if w in lower]
    if absolute_hits:
        score -= min(20, 7 * len(absolute_hits))
        logs.append({"type": "negative",
                     "text": f"Absolutist/unfalsifiable language detected ({', '.join(absolute_hits[:3])})."})

    vague_hits = [p for p in UNVERIFIED_ATTRIBUTION_PHRASES if p in lower]
    if vague_hits:
        score -= 15
        logs.append({"type": "negative",
                     "text": f"Claim is attributed to an unnamed/vague source ('{vague_hits[0]}')."})

    named_match = NAMED_ATTRIBUTION_PATTERN.search(headline)
    if named_match:
        score += 12
        logs.append({"type": "positive",
                     "text": f"Claim is attributed to a specific, named source ({named_match.group(1)})."})

    if LISTICLE_PATTERN.match(headline):
        score -= 15
        logs.append({"type": "negative", "text": "Headline follows a listicle/clickbait numbering pattern."})

    emoji_count = len(EMOJI_PATTERN.findall(headline))
    if emoji_count > 0:
        score -= min(15, emoji_count * 5)
        logs.append({"type": "warning", "text": "Emoji usage detected in headline - unusual for hard news reporting."})

    return score, logs


def extract_search_keywords(headline: str):
    """
    Pulls out the most meaningful terms for querying the live news feed,
    preferring noun phrases (proper nouns, named entities, topics) over
    the raw crisis keyword list, since noun phrases search far more
    precisely than single generic words like 'war' or 'sanction'.
    """
    try:
        blob = TextBlob(headline)
        phrases = [p for p in blob.noun_phrases if len(p.split()) <= 4]
    except Exception:
        phrases = []
    if phrases:
        return phrases[:3]
    detected = [w for w in GLOBAL_CRISIS_KEYWORDS if w in headline.lower()]
    return detected[:2]


async def check_live_global_coverage(headline: str):
    """
    Scans the headline for critical global events / notable topics and
    queries an external news feed to see whether the story is actually
    being covered anywhere, with short-term caching to avoid duplicate
    API calls for near-identical headlines during a demo session.
    """
    detected_crisis = [word for word in GLOBAL_CRISIS_KEYWORDS if word in headline.lower()]
    keywords = extract_search_keywords(headline)
    if not detected_crisis and not keywords:
        return 0, []

    logs = []
    if detected_crisis:
        logs.append({"type": "warning",
                     "text": f"Global impact topic detected: {', '.join(detected_crisis)}. Cross-referencing live databases..."})

    search_terms = keywords if keywords else detected_crisis[:2]
    search_query = " AND ".join(search_terms) if search_terms else headline[:60]

    cached = _NEWS_CACHE.get(search_query)
    if cached and (time.time() - cached[0]) < _NEWS_CACHE_TTL_SECONDS:
        cached_score, cached_logs = cached[1]
        return cached_score, logs + cached_logs + [{"type": "warning", "text": "(cached result)"}]

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
                    result_logs = [{"type": "positive", "text": "Active global news coverage confirms this topic is currently trending across major networks."}]
                    result = (15, result_logs)
                elif total_results > 0:
                    result_logs = [{"type": "warning", "text": f"Minor real-time coverage found ({total_results} matching items). Situation may be developing."}]
                    result = (5, result_logs)
                else:
                    result_logs = [{"type": "negative", "text": "Warning: High-impact claim detected, but zero live matching coverage found from trusted sources. Likely false."}]
                    result = (-30, result_logs)

                _NEWS_CACHE[search_query] = (time.time(), result)
                return result[0], logs + result[1]
            else:
                logs.append({"type": "warning", "text": "Live news verification service is temporarily unavailable. Proceeding with standard static analysis."})
                return 0, logs
    except Exception:
        logs.append({"type": "warning", "text": "Network timeout while checking global news feeds. Proceeding with standard static analysis."})
        return 0, logs


def compute_verdict(score: int) -> str:
    if score >= 80:
        return "Highly Trustworthy"
    if score >= 60:
        return "Generally Trustworthy"
    if score >= 40:
        return "Use Caution"
    if score >= 20:
        return "Likely Misleading"
    return "High Risk of Misinformation"


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
    source_score, ling_score, form_score, claim_score = 50, 75, 90, 70
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
        else:
            spoof_target = check_typosquatting(hostname)
            if spoof_target:
                source_score -= 45
                audit_log.append({"type": "negative",
                                   "text": f"Domain '{hostname}' closely resembles trusted domain '{spoof_target}' - possible impersonation."})
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

    if abs(analysis.sentiment.polarity) > 0.5:
        ling_score -= 10
        audit_log.append({"type": "warning", "text": "Strongly emotionally charged wording detected (very positive or very negative)."})

    # 3. Structural Formatting Evaluation
    if re.search(r'(!!+|\?\?+|\?!|!\?)', headline):
        form_score -= 25
        audit_log.append({"type": "negative", "text": "Exaggerated punctuation detected (e.g., !! or ??)."})
    if headline.isupper():
        form_score -= 30
        audit_log.append({"type": "negative", "text": "Headline is written entirely in uppercase (ALL CAPS). Highly unprofessional."})

    caps_words = [w for w in re.findall(r'\b[A-Z]{4,}\b', headline)]
    if caps_words and not headline.isupper():
        form_score -= min(15, 5 * len(caps_words))
        audit_log.append({"type": "warning", "text": f"Selective all-caps words used for emphasis ({', '.join(caps_words[:3])})."})

    # 4. Claim Language Analysis (new)
    claim_delta, claim_logs = analyze_claim_language(headline)
    claim_score += claim_delta
    audit_log.extend(claim_logs)

    # 5. Live News Verification Layer (Async, now cached + entity-aware)
    live_score_modifier, live_logs = await check_live_global_coverage(headline)
    audit_log.extend(live_logs)

    # Normalize localized matrix calculations to fit within 5-98 bounds
    norm_source = max(5, min(98, source_score))
    norm_ling = max(5, min(98, ling_score))
    norm_form = max(5, min(98, form_score))
    norm_claim = max(5, min(98, claim_score))

    # Incorporate the live context score modifier directly into the core calculations
    calculated_score = int(
        (norm_source * 0.30) + (norm_ling * 0.25) + (norm_form * 0.15) + (norm_claim * 0.30)
    ) + live_score_modifier
    final_score = max(5, min(98, calculated_score))
    verdict = compute_verdict(final_score)

    record = {"url": url, "head": headline, "score": final_score, "verdict": verdict,
              "date": datetime.datetime.now().strftime("%I:%M %p")}

    # Store history
    fake_db[payload.username]["history"].insert(0, record)
    fake_db[payload.username]["history"] = fake_db[payload.username]["history"][:5]
    return {
        "validData": True,
        "finalTrustScore": final_score,
        "verdict": verdict,
        "sourceScore": norm_source,
        "lingScore": norm_ling,
        "formScore": norm_form,
        "claimScore": norm_claim,
        "auditLog": audit_log,
        "newHistory": fake_db[payload.username]["history"]
    }

# --- SERVE FRONTEND ---
@app.get("/")
async def serve_frontend():
    return FileResponse("index.html")
