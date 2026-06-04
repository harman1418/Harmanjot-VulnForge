from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
import time
import jwt
import os
import re
from collections import defaultdict
from routers import (
    portscan, subdomain, whois_lookup, headers, waf,
    ssl_scan, wpscan, sqli, xss, nuclei_scan,
    gobuster_scan, hydra_scan, auth, fullscan, history, targets,
    google_dork, cors_check, subdomain_takeover, jwt_scan,
    robots_txt, cookie_check, clickjacking, dns_brute, vhost, api_scan, drupal, joomla, email_harvester, shodan_scan, reverse_ip, tech_detect
)

app = FastAPI(title="VulnForge API", version="2.0.0")

# ==========================================
# 1. BULLETPROOF SECURITY HEADERS
# ==========================================
class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none';"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        if "server" in response.headers:
            del response.headers["server"]
        return response

app.add_middleware(SecurityHeadersMiddleware)

# ==========================================
# 2. STRICT CORS POLICY
# ==========================================
app.add_middleware(
    CORSMiddleware,
    # Allow production domain AND localhost for when you are testing locally
    allow_origins=[
        "https://vulnforge.app", 
        "https://www.vulnforge.app", 
        "http://vulnforge.app", 
        "http://www.vulnforge.app", 
        "http://localhost:5173", 
        "http://localhost:3000"
    ], 
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

# ==========================================
# 3. GLOBAL SECURITY ENFORCEMENT
# ==========================================
JWT_SECRET = os.getenv("SECRET_KEY", "vulnforge_secret_2024")
JWT_ALGORITHM = "HS256"

# Rate limit configurations (Max 60 requests per minute)
RATE_LIMIT_WINDOW = 60
RATE_LIMIT_MAX = 60
ip_requests = defaultdict(list)

EXCLUDED_AUTH_PATHS = [
    "/api/auth/login",
    "/api/auth/register",
    "/api/auth/verify-otp",
    "/api/auth/resend-otp",
    "/api/auth/forgot-password",
    "/api/auth/reset-password",
    "/health",
    "/"
]

class SecurityEnforcementMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # 1. Allow browser preflight
        if request.method == "OPTIONS":
            return await call_next(request)

        # 2. Block Command Injection (Strict Target Validation)
        target_param = request.query_params.get("target")
        if target_param:
            clean_target = target_param.replace("http://", "").replace("https://", "")
            # Allow valid URL chars (letters, digits, dots, slashes, query params, etc.)
            # Block shell metacharacters: ; | ` $ ( ) { } < > ! \
            if re.search(r'[;|`$(){}<>!\\]', clean_target) or '  ' in clean_target:
                origin = request.headers.get("origin", "")
                return JSONResponse(
                    status_code=400, 
                    content={"detail": "Security Violation: Invalid target format."},
                    headers={"Access-Control-Allow-Origin": origin, "Access-Control-Allow-Credentials": "true"} if origin else {}
                )

        # 3. Apply IP Rate Limiting
        ip = request.client.host if request.client else "127.0.0.1"
        now = time.time()
        ip_requests[ip] = [t for t in ip_requests[ip] if now - t < RATE_LIMIT_WINDOW]
        
        if len(ip_requests[ip]) >= RATE_LIMIT_MAX:
            return Response(content='{"detail": "Rate limit exceeded. Please wait."}', status_code=429, media_type="application/json")
        ip_requests[ip].append(now)

        # 4. Enforce JWT Authentication for all Scanners
        path = request.url.path
        if not any(path.startswith(ex) for ex in EXCLUDED_AUTH_PATHS):
            auth_header = request.headers.get("authorization") or request.cookies.get("access_token", "")
            if auth_header:
                auth_header = auth_header.strip().strip('"')
            
            if not auth_header or not auth_header.startswith("Bearer "):
                return JSONResponse(status_code=401, content={"detail": "Missing or invalid authentication token"})
            
            token = auth_header.split(" ")[1]
            try:
                payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
                request.state.user = payload
            except jwt.ExpiredSignatureError:
                return Response(content='{"detail": "Unauthorized: Token expired."}', status_code=401, media_type="application/json")
            except Exception:
                return Response(content='{"detail": "Unauthorized: Invalid token."}', status_code=401, media_type="application/json")

        return await call_next(request)

app.add_middleware(SecurityEnforcementMiddleware)

# ==========================================
# 4. ALL ROUTER INCLUSIONS
# ==========================================
app.include_router(portscan.router,      prefix="/api/portscan",   tags=["Port Scanner"])
app.include_router(subdomain.router,     prefix="/api/subdomain",  tags=["Subdomain Finder"])
app.include_router(whois_lookup.router,  prefix="/api/whois",      tags=["Whois Lookup"])
app.include_router(headers.router,       prefix="/api/headers",    tags=["Header Fingerprint"])
app.include_router(waf.router,           prefix="/api/waf",        tags=["WAF Detector"])
app.include_router(ssl_scan.router,      prefix="/api/ssl",        tags=["SSL Scanner"])
app.include_router(wpscan.router,        prefix="/api/wpscan",     tags=["WordPress Scanner"])
app.include_router(sqli.router,          prefix="/api/sqli",       tags=["SQLi Scanner"])
app.include_router(xss.router,           prefix="/api/xss",        tags=["XSS Scanner"])
app.include_router(nuclei_scan.router,   prefix="/api/nuclei",     tags=["CVE Scanner"])
app.include_router(gobuster_scan.router, prefix="/api/gobuster",   tags=["URL Fuzzer"])
app.include_router(hydra_scan.router,    prefix="/api/hydra",      tags=["Password Auditor"])
app.include_router(auth.router,          prefix="/api/auth",       tags=["Authentication"])
app.include_router(fullscan.router,      prefix="/api/fullscan",   tags=["Full Scan"])
app.include_router(history.router,       prefix="/api/history",    tags=["Scan History"])
app.include_router(targets.router,       prefix="/api/targets",    tags=["Targets"])
app.include_router(google_dork.router,   prefix="/api/dork",       tags=["Google Dorking"])
app.include_router(cors_check.router,    prefix="/api/cors",       tags=["CORS Checker"])
app.include_router(subdomain_takeover.router, prefix="/api/takeover",   tags=["Subdomain Takeover"])
app.include_router(jwt_scan.router,      prefix="/api/jwt",        tags=["JWT Scanner"])
app.include_router(robots_txt.router,    prefix="/api/robots",     tags=["Robots Analyzer"])
app.include_router(cookie_check.router,  prefix="/api/cookie",     tags=["Cookie Security"])
app.include_router(clickjacking.router,  prefix="/api/clickjacking", tags=["Clickjacking Tester"])
app.include_router(dns_brute.router,     prefix="/api/dns_brute",  tags=["DNS Brute"])
app.include_router(vhost.router,         prefix="/api/vhost",      tags=["VHost Finder"])
app.include_router(api_scan.router,      prefix="/api/api_scan",   tags=["API Scanner"])
app.include_router(drupal.router,        prefix="/api/drupal",     tags=["Drupal Scanner"])
app.include_router(joomla.router,        prefix="/api/joomla",     tags=["Joomla Scanner"])
app.include_router(email_harvester.router, prefix="/api/harvester", tags=["Email Harvester"])
app.include_router(shodan_scan.router,   prefix="/api/shodan",     tags=["Shodan Scanner"])
app.include_router(reverse_ip.router,    prefix="/api/reverse_ip", tags=["Reverse IP"])
app.include_router(tech_detect.router,   prefix="/api/tech",       tags=["Tech Detect"])

@app.get("/")
def root():
    return {"name": "VulnForge", "status": "online", "version": "2.0.0"}

@app.get("/health")
def health():
    return {"status": "healthy"}
