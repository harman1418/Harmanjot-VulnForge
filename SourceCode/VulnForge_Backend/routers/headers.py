from fastapi import APIRouter
import httpx
import concurrent.futures

router = APIRouter()

def _detect_tech(url):
    """Try builtwith with a timeout — returns {} if it hangs."""
    try:
        import builtwith
        return builtwith.parse(url)
    except:
        return {}

@router.get("/")
def header_fingerprint(target: str):
    try:
        if not target.startswith("http"):
            url = f"https://{target}"
        else:
            url = target

        # Fetch headers
        response = httpx.get(
            url,
            follow_redirects=True,
            timeout=15,
            verify=False
        )

        headers = dict(response.headers)

        # Detect technologies (with 8s timeout to prevent hanging)
        technologies = {}
        try:
            with concurrent.futures.ThreadPoolExecutor() as executor:
                future = executor.submit(_detect_tech, url)
                technologies = future.result(timeout=8)
        except (concurrent.futures.TimeoutError, Exception):
            technologies = {}

        # Security headers check
        missing_headers = []
        security_headers = {}
        sec_checks = {
            "X-Frame-Options": "x-frame-options",
            "X-Content-Type-Options": "x-content-type-options",
            "Strict-Transport-Security": "strict-transport-security",
            "Content-Security-Policy": "content-security-policy",
            "X-XSS-Protection": "x-xss-protection",
            "Referrer-Policy": "referrer-policy",
            "Permissions-Policy": "permissions-policy",
        }

        for display_name, header_key in sec_checks.items():
            val = headers.get(header_key, "")
            if val:
                security_headers[display_name] = val
            else:
                security_headers[display_name] = "❌ Missing"
                missing_headers.append(display_name)

        return {
            "target": target,
            "status": "success",
            "status_code": response.status_code,
            "headers": headers,
            "security_headers": security_headers,
            "missing_headers": missing_headers,
            "technologies": technologies,
            "server": headers.get("server", "Unknown"),
        }

    except httpx.TimeoutException:
        return {"status": "error", "message": "Connection timed out"}
    except Exception as e:
        return {"status": "error", "message": str(e)}
