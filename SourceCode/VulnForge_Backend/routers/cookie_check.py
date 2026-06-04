from fastapi import APIRouter
import httpx

router = APIRouter()

@router.get("/")
def cookie_security_checker(target: str):
    try:
        url = f"https://{target}" if not target.startswith("http") else target
        response = httpx.get(url, follow_redirects=True, timeout=15, verify=False)
        
        cookies_analyzed = []
        issues_found = set()
        
        for cookie in response.cookies.jar:
            issues = []
            if not cookie.secure:
                issues.append("Missing Secure flag")
            
            # Check HttpOnly & SameSite via dict lookup
            rest_attrs = {k.lower(): v for k, v in cookie._rest.items()} if hasattr(cookie, '_rest') else {}
            
            if 'httponly' not in rest_attrs:
                issues.append("Missing HttpOnly flag")
            
            samesite = rest_attrs.get('samesite', None)
            if not samesite or samesite.lower() == 'none':
                if not cookie.secure:
                    issues.append("SameSite=None but missing Secure flag")
            
            cookies_analyzed.append({
                "name": cookie.name,
                "domain": cookie.domain,
                "issues": issues
            })
            
            for i in issues:
                issues_found.add(i)
                
        return {
            "target": target,
            "status": "success",
            "total_cookies": len(cookies_analyzed),
            "vulnerable_cookies": len([c for c in cookies_analyzed if c["issues"]]),
            "issues_summary": list(issues_found),
            "details": cookies_analyzed
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}
