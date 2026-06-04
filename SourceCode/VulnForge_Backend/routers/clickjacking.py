from fastapi import APIRouter
import httpx

router = APIRouter()

@router.get("/")
def clickjacking_tester(target: str):
    try:
        url = f"https://{target}" if not target.startswith("http") else target
        response = httpx.get(url, follow_redirects=True, timeout=10, verify=False)
        
        headers = {k.lower(): v.lower() for k, v in response.headers.items()}
        
        x_frame_options = headers.get("x-frame-options", None)
        csp = headers.get("content-security-policy", None)
        
        vulnerable = True
        protection_mechanism = []
        
        if x_frame_options in ["deny", "sameorigin"]:
            vulnerable = False
            protection_mechanism.append(f"X-Frame-Options: {x_frame_options}")
            
        if csp and "frame-ancestors" in csp:
            vulnerable = False
            protection_mechanism.append("CSP: frame-ancestors present")
            
        return {
            "target": target,
            "status": "success",
            "is_vulnerable": vulnerable,
            "x_frame_options": x_frame_options or "Missing",
            "csp": csp or "Missing",
            "protections": protection_mechanism
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}
