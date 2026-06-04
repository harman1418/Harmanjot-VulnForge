from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from utils.database import users_collection, otps_collection
from utils.email import generate_otp, send_otp_email
from datetime import datetime, timedelta
import hashlib
import bcrypt
import os
import jwt
import uuid
from collections import defaultdict
import time
import httpx

router = APIRouter()

JWT_SECRET       = os.getenv("SECRET_KEY", "vulnforge_secret_2024")
JWT_ALGORITHM    = "HS256"
JWT_EXPIRY_HOURS = 24

# ─── Brute Force Config ───────────────────────────────────────────────────────
LOGIN_MAX_ATTEMPTS = 5
LOGIN_WINDOW       = 300    # 5 min rolling window
LOGIN_LOCKOUT      = 7200   # 2 hours

OTP_MAX_ATTEMPTS   = 8
OTP_WINDOW         = 600    # 10 min rolling window
OTP_LOCKOUT        = 7200   # 2 hours

RESEND_MAX         = 5
RESEND_WINDOW      = 3600   # 1 hour

# In-memory stores: {key: {"attempts": [timestamps], "locked_until": float}}
login_store = defaultdict(lambda: {"attempts": [], "locked_until": 0.0})
otp_store   = defaultdict(lambda: {"attempts": [], "locked_until": 0.0})


# ─── Brute Force Helpers ──────────────────────────────────────────────────────

def _format_wait(seconds: int) -> str:
    h = seconds // 3600
    m = (seconds % 3600) // 60
    s = seconds % 60
    if h > 0:
        return f"{h}h {m}m"
    if m > 0:
        return f"{m}m {s}s"
    return f"{s}s"


def _check(store, key, max_attempts, window, lockout, label="attempts"):
    now = time.time()
    rec = store[key]

    # Still locked?
    if rec["locked_until"] > now:
        wait = int(rec["locked_until"] - now)
        raise HTTPException(
            status_code=429,
            detail=f"Too many failed {label}. Try again in {_format_wait(wait)}."
        )

    # Prune old attempts
    rec["attempts"] = [t for t in rec["attempts"] if now - t < window]

    # About to exceed?
    if len(rec["attempts"]) >= max_attempts:
        rec["locked_until"] = now + lockout
        rec["attempts"]     = []
        raise HTTPException(
            status_code=429,
            detail=f"Too many failed {label}. Account locked for 2 hours."
        )


def _fail(store, key):
    store[key]["attempts"].append(time.time())


def _remaining(store, key, max_attempts) -> int:
    return max(0, max_attempts - len(store[key]["attempts"]))


def _clear(store, key):
    store[key] = {"attempts": [], "locked_until": 0.0}


# ─── JWT Helpers ──────────────────────────────────────────────────────────────

def hash_password(password: str) -> str:
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

def verify_password(plain_password: str, stored_hash: str) -> bool:
    if stored_hash.startswith("$2"):
        return bcrypt.checkpw(plain_password.encode('utf-8'), stored_hash.encode('utf-8'))
    else:
        return hashlib.sha256(plain_password.encode()).hexdigest() == stored_hash


def create_token(user_id: str, email: str, name: str) -> str:
    payload = {
        "user_id": user_id,
        "email":   email,
        "name":    name,
        "exp":     datetime.utcnow() + timedelta(hours=JWT_EXPIRY_HOURS)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def verify_token(token: str):
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except Exception:
        return None


# ─── Models ───────────────────────────────────────────────────────────────────

class RegisterRequest(BaseModel):
    email: str
    password: str
    name: str


class VerifyOTPRequest(BaseModel):
    email: str
    otp: str


class LoginRequest(BaseModel):
    email: str
    password: str


class ResendOTPRequest(BaseModel):
    email: str


class ForgotPasswordRequest(BaseModel):
    email: str


class ResetPasswordRequest(BaseModel):
    email: str
    otp: str
    new_password: str


# ─── Routes ───────────────────────────────────────────────────────────────────

@router.post("/register")
async def register(req: RegisterRequest, request: Request):
    ip     = request.client.host
    rk     = f"register:{ip}"

    # Limit registration attempts per IP (10 per hour)
    _check(otp_store, rk, 10, 3600, OTP_LOCKOUT, "registration attempts")

    if len(req.password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")

    existing = await users_collection.find_one({"email": req.email})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")

    otp    = generate_otp()
    expiry = datetime.utcnow() + timedelta(minutes=10)

    await otps_collection.delete_many({"email": req.email})
    await otps_collection.insert_one({
        "email":  req.email,
        "otp":    otp,
        "expiry": expiry,
        "type":   "register",
        "user_data": {
            "email":    req.email,
            "password": hash_password(req.password),
            "name":     req.name
        }
    })

    _fail(otp_store, rk)
    send_otp_email(req.email, otp)
    return {"status": "success", "message": "OTP sent to your email"}


@router.post("/verify-otp")
async def verify_otp(req: VerifyOTPRequest, request: Request):
    ip  = request.client.host
    key = f"otp:{req.email}:{ip}"

    # OTP brute force — 8 attempts → 2hr lockout
    _check(otp_store, key, OTP_MAX_ATTEMPTS, OTP_WINDOW, OTP_LOCKOUT, "OTP attempts")

    otp_doc = await otps_collection.find_one({"email": req.email, "type": "register"})

    if not otp_doc:
        raise HTTPException(status_code=400, detail="No pending verification found. Please register again.")

    if datetime.utcnow() > otp_doc["expiry"]:
        await otps_collection.delete_many({"email": req.email, "type": "register"})
        raise HTTPException(status_code=400, detail="OTP expired. Please register again.")

    if otp_doc["otp"] != req.otp:
        _fail(otp_store, key)
        rem = _remaining(otp_store, key, OTP_MAX_ATTEMPTS)
        raise HTTPException(
            status_code=400,
            detail=f"Invalid OTP. {rem} attempt(s) remaining before 2-hour lockout."
        )

    # Success
    _clear(otp_store, key)

    user_data = otp_doc["user_data"]
    user_id   = str(uuid.uuid4())

    await users_collection.insert_one({
        "_id":        user_id,
        "email":      user_data["email"],
        "password":   user_data["password"],
        "name":       user_data["name"],
        "created_at": datetime.utcnow().isoformat()
    })

    await otps_collection.delete_many({"email": req.email})

    token = create_token(user_id, user_data["email"], user_data["name"])
    
    response = JSONResponse(content={
        "status":  "success",
        "message": "Account verified successfully",
        "user": {
            "user_id": user_id,
            "email":   user_data["email"],
            "name":    user_data["name"]
        }
    })
    response.set_cookie(
        key="access_token",
        value=f"Bearer {token}",
        httponly=True,
        secure=True,
        samesite="lax",
        domain=".vulnforge.app",
        max_age=JWT_EXPIRY_HOURS * 3600
    )
    return response


@router.post("/resend-otp")
async def resend_otp(req: ResendOTPRequest, request: Request):
    ip  = request.client.host
    key = f"resend:{req.email}:{ip}"

    # Max 5 resends per hour
    _check(otp_store, key, RESEND_MAX, RESEND_WINDOW, OTP_LOCKOUT, "resend attempts")

    otp_doc = await otps_collection.find_one({"email": req.email})
    if not otp_doc:
        raise HTTPException(status_code=400, detail="No pending verification for this email")

    otp    = generate_otp()
    expiry = datetime.utcnow() + timedelta(minutes=10)

    await otps_collection.update_one(
        {"email": req.email},
        {"$set": {"otp": otp, "expiry": expiry}}
    )

    _fail(otp_store, key)
    send_otp_email(req.email, otp)
    return {"status": "success", "message": "OTP resent to your email"}


@router.post("/login")
async def login(req: LoginRequest, request: Request):
    ip  = request.client.host
    key = f"login:{ip}"

    # Login brute force — 5 attempts → 2hr lockout
    _check(login_store, key, LOGIN_MAX_ATTEMPTS, LOGIN_WINDOW, LOGIN_LOCKOUT, "login attempts")

    user = await users_collection.find_one({"email": req.email})

    if not user or not verify_password(req.password, user["password"]):
        _fail(login_store, key)
        rem = _remaining(login_store, key, LOGIN_MAX_ATTEMPTS)
        if rem == 0:
            raise HTTPException(
                status_code=429,
                detail="Too many failed attempts. Account locked for 2 hours."
            )
        raise HTTPException(
            status_code=400,
            detail=f"Invalid email or password. {rem} attempt(s) remaining before 2-hour lockout."
        )

    _clear(login_store, key)

    user_id = str(user.get("_id", user.get("user_id", "")))
    token   = create_token(user_id, user["email"], user["name"])

    response = JSONResponse(content={
        "status":  "success",
        "message": "Login successful",
        "user": {
            "user_id": user_id,
            "email":   user["email"],
            "name":    user["name"]
        }
    })
    response.set_cookie(
        key="access_token",
        value=f"Bearer {token}",
        httponly=True,
        secure=True,
        samesite="lax",
        domain=".vulnforge.app",
        max_age=JWT_EXPIRY_HOURS * 3600
    )
    return response


@router.post("/forgot-password")
async def forgot_password(req: ForgotPasswordRequest, request: Request):
    ip  = request.client.host
    key = f"forgot:{ip}"

    # Limit forgot-password requests — 3 per 10 min
    _check(otp_store, key, 3, 600, OTP_LOCKOUT, "reset attempts")
    _fail(otp_store, key)

    user = await users_collection.find_one({"email": req.email})
    if not user:
        # Don't reveal whether email exists
        return {"status": "success", "message": "If this email exists, a reset code has been sent"}

    otp    = generate_otp()
    expiry = datetime.utcnow() + timedelta(minutes=10)

    await otps_collection.delete_many({"email": req.email, "type": "reset"})
    await otps_collection.insert_one({
        "email":  req.email,
        "otp":    otp,
        "expiry": expiry,
        "type":   "reset"
    })

    send_otp_email(req.email, otp)
    return {"status": "success", "message": "If this email exists, a reset code has been sent"}


@router.post("/reset-password")
async def reset_password(req: ResetPasswordRequest, request: Request):
    ip  = request.client.host
    key = f"reset:{req.email}:{ip}"

    # OTP brute force on reset — 8 attempts → 2hr lockout
    _check(otp_store, key, OTP_MAX_ATTEMPTS, OTP_WINDOW, OTP_LOCKOUT, "reset OTP attempts")

    otp_doc = await otps_collection.find_one({"email": req.email, "type": "reset"})

    if not otp_doc:
        raise HTTPException(status_code=400, detail="Invalid or expired reset code")

    if datetime.utcnow() > otp_doc["expiry"]:
        await otps_collection.delete_many({"email": req.email, "type": "reset"})
        raise HTTPException(status_code=400, detail="Reset code expired. Please request a new one.")

    if otp_doc["otp"] != req.otp:
        _fail(otp_store, key)
        rem = _remaining(otp_store, key, OTP_MAX_ATTEMPTS)
        raise HTTPException(
            status_code=400,
            detail=f"Invalid reset code. {rem} attempt(s) remaining before 2-hour lockout."
        )

    if len(req.new_password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")

    _clear(otp_store, key)

    await users_collection.update_one(
        {"email": req.email},
        {"$set": {"password": hash_password(req.new_password)}}
    )

    await otps_collection.delete_many({"email": req.email, "type": "reset"})
    return {"status": "success", "message": "Password reset successfully"}


@router.post("/logout")
async def logout():
    response = JSONResponse(content={"status": "success", "message": "Logged out successfully"})
    response.delete_cookie(key="access_token", secure=True, samesite="lax", domain=".vulnforge.app")
    return response

@router.get("/me")
async def get_me(request: Request):
    auth = request.headers.get("authorization") or request.cookies.get("access_token", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Not authenticated")
    token   = auth.split(" ")[1]
    payload = verify_token(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    return {"status": "success", "user": payload}

# ─── OAuth Routes (Production Integration) ─────────────────────────────────────

GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
GOOGLE_REDIRECT_URI = os.getenv("GOOGLE_REDIRECT_URI", "https://api.vulnforge.app/api/auth/google/callback")

@router.get("/google/login")
async def google_login():
    if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
        raise HTTPException(status_code=500, detail="Google OAuth is not configured on the server")
    # Redirect the user's browser directly to Google's OAuth 2.0 authorization screen
    scope = "openid email profile"
    auth_url = f"https://accounts.google.com/o/oauth2/v2/auth?client_id={GOOGLE_CLIENT_ID}&redirect_uri={GOOGLE_REDIRECT_URI}&response_type=code&scope={scope}"
    return Response(status_code=302, headers={"Location": auth_url})

@router.get("/google/callback")
async def google_callback(code: str = None):
    if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
        raise HTTPException(status_code=500, detail="Google OAuth is not configured on the server")
    if not code:
        raise HTTPException(status_code=400, detail="Missing authorization code from Google")
    
    async with httpx.AsyncClient() as client:
        # Step 1: Exchange authorization code for access token
        token_url = "https://oauth2.googleapis.com/token"
        token_data = {
            "client_id": GOOGLE_CLIENT_ID,
            "client_secret": GOOGLE_CLIENT_SECRET,
            "code": code,
            "grant_type": "authorization_code",
            "redirect_uri": GOOGLE_REDIRECT_URI
        }
        
        try:
            token_res = await client.post(token_url, data=token_data)
            if token_res.status_code != 200:
                raise HTTPException(status_code=400, detail=f"Failed to fetch token from Google: {token_res.text}")
            
            tokens = token_res.json()
            access_token = tokens.get("access_token")
            
            # Step 2: Fetch user info using the access token
            userinfo_url = "https://www.googleapis.com/oauth2/v3/userinfo"
            user_res = await client.get(userinfo_url, headers={"Authorization": f"Bearer {access_token}"})
            if user_res.status_code != 200:
                raise HTTPException(status_code=400, detail="Failed to fetch user details from Google")
            
            google_user = user_res.json()
            email = google_user.get("email")
            name = google_user.get("name", email.split('@')[0])
            picture = google_user.get("picture")
            
        except httpx.RequestError as exc:
            raise HTTPException(status_code=502, detail=f"Google API communication error: {exc}")

    # Step 3: Check if user exists or create automatically
    user = await users_collection.find_one({"email": email})
    if not user:
        user_id = str(uuid.uuid4())
        await users_collection.insert_one({
            "_id": user_id,
            "email": email,
            "name": name,
            "created_at": datetime.utcnow().isoformat(),
            "auth_provider": "google",
            "picture": picture
        })
    else:
        user_id = str(user.get("_id", user.get("user_id", "")))
        # Polish: Link Google OAuth details to the existing account
        update_data = {}
        if not user.get("picture") and picture:
            update_data["picture"] = picture
        if not user.get("auth_provider"):
            update_data["auth_provider"] = "google"
        if update_data:
            await users_collection.update_one({"_id": user_id}, {"$set": update_data})

    # Step 4: Issue JWT token
    token = create_token(user_id, email, name)
    
    # Step 5: Set HttpOnly Cookie and redirect to frontend Login Callback
    frontend_url = os.getenv("FRONTEND_URL", "https://vulnforge.app")
    response = Response(status_code=302, headers={"Location": f"{frontend_url}/login?oauth_success=true"})
    response.set_cookie(
        key="access_token",
        value=f"Bearer {token}",
        httponly=True,
        secure=True,
        samesite="lax",
        domain=".vulnforge.app",
        max_age=JWT_EXPIRY_HOURS * 3600
    )
    return response

GITHUB_CLIENT_ID = os.getenv("GITHUB_CLIENT_ID")
GITHUB_CLIENT_SECRET = os.getenv("GITHUB_CLIENT_SECRET")
GITHUB_REDIRECT_URI = os.getenv("GITHUB_REDIRECT_URI", "https://api.vulnforge.app/api/auth/github/callback")

@router.get("/github/login")
async def github_login():
    if not GITHUB_CLIENT_ID or not GITHUB_CLIENT_SECRET:
        raise HTTPException(status_code=500, detail="GitHub OAuth is not configured on the server")
    # Redirect user to GitHub OAuth authorization endpoint
    scope = "user:email"
    auth_url = f"https://github.com/login/oauth/authorize?client_id={GITHUB_CLIENT_ID}&redirect_uri={GITHUB_REDIRECT_URI}&scope={scope}"
    return Response(status_code=302, headers={"Location": auth_url})

@router.get("/github/callback")
async def github_callback(code: str = None):
    if not GITHUB_CLIENT_ID or not GITHUB_CLIENT_SECRET:
        raise HTTPException(status_code=500, detail="GitHub OAuth is not configured on the server")
    if not code:
        raise HTTPException(status_code=400, detail="Missing authorization code from GitHub")
    
    async with httpx.AsyncClient() as client:
        # Step 1: Exchange code for access token
        token_url = "https://github.com/login/oauth/access_token"
        headers = {"Accept": "application/json"}
        token_data = {
            "client_id": GITHUB_CLIENT_ID,
            "client_secret": GITHUB_CLIENT_SECRET,
            "code": code,
            "redirect_uri": GITHUB_REDIRECT_URI
        }
        
        try:
            token_res = await client.post(token_url, headers=headers, json=token_data)
            if token_res.status_code != 200:
                raise HTTPException(status_code=400, detail=f"Failed to fetch token from GitHub: {token_res.text}")
            
            tokens = token_res.json()
            access_token = tokens.get("access_token")
            if not access_token:
                raise HTTPException(status_code=400, detail="Could not obtain access token from GitHub response")
            
            # Step 2: Fetch user profile (GitHub requires a User-Agent)
            api_headers = {
                "Authorization": f"Bearer {access_token}",
                "User-Agent": "VulnForge-Backend"
            }
            user_res = await client.get("https://api.github.com/user", headers=api_headers)
            if user_res.status_code != 200:
                raise HTTPException(status_code=400, detail="Failed to fetch user profile from GitHub")
            
            github_user = user_res.json()
            name = github_user.get("name") or github_user.get("login")
            picture = github_user.get("avatar_url")
            
            # Step 3: Fetch emails because GitHub user email can be null if set to private
            email = github_user.get("email")
            if not email:
                email_res = await client.get("https://api.github.com/user/emails", headers=api_headers)
                if email_res.status_code == 200:
                    emails = email_res.json()
                    # Find primary verified email, or fall back to first email
                    primary_email = next((e["email"] for e in emails if e.get("primary") and e.get("verified")), None)
                    if not primary_email:
                        primary_email = next((e["email"] for e in emails if e.get("primary")), None)
                    if not primary_email and emails:
                        primary_email = emails[0].get("email")
                    
                    email = primary_email
            
            if not email:
                raise HTTPException(status_code=400, detail="Could not retrieve a valid email address from your GitHub account")

        except httpx.RequestError as exc:
            raise HTTPException(status_code=502, detail=f"GitHub API communication error: {exc}")

    # Step 4: Check if user exists or auto-register
    user = await users_collection.find_one({"email": email})
    if not user:
        user_id = str(uuid.uuid4())
        await users_collection.insert_one({
            "_id": user_id,
            "email": email,
            "name": name,
            "created_at": datetime.utcnow().isoformat(),
            "auth_provider": "github",
            "picture": picture
        })
    else:
        user_id = str(user.get("_id", user.get("user_id", "")))
        # Polish: Link GitHub OAuth details to the existing account
        update_data = {}
        if not user.get("picture") and picture:
            update_data["picture"] = picture
        if not user.get("auth_provider"):
            update_data["auth_provider"] = "github"
        if update_data:
            await users_collection.update_one({"_id": user_id}, {"$set": update_data})

    # Step 5: Generate JWT session token
    token = create_token(user_id, email, name)
    
    # Step 6: Redirect to frontend success route with state cookie
    frontend_url = os.getenv("FRONTEND_URL", "https://vulnforge.app")
    response = Response(status_code=302, headers={"Location": f"{frontend_url}/login?oauth_success=true"})
    response.set_cookie(
        key="access_token",
        value=f"Bearer {token}",
        httponly=True,
        secure=True,
        samesite="lax",
        domain=".vulnforge.app",
        max_age=JWT_EXPIRY_HOURS * 3600
    )
    return response
