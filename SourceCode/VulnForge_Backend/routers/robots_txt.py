from fastapi import APIRouter
import httpx

router = APIRouter()

@router.get("/")
def robots_analyzer(target: str):
    try:
        url = f"https://{target}/robots.txt" if not target.startswith("http") else f"{target}/robots.txt"
        
        response = httpx.get(url, follow_redirects=True, timeout=10, verify=False)
        
        if response.status_code == 200:
            lines = response.text.split("\n")
            disallowed = [line.split("Disallow:")[1].strip() for line in lines if "Disallow:" in line]
            sitemaps = [line.split("Sitemap:")[1].strip() for line in lines if "Sitemap:" in line]
            
            # Look for sensitive paths
            sensitive_keywords = ["admin", "login", "api", "config", "backup", "db", "private", "secret"]
            sensitive_paths = [path for path in disallowed if any(kw in path.lower() for kw in sensitive_keywords)]
            
            return {
                "target": target,
                "status": "success",
                "status_code": 200,
                "found": True,
                "disallowed_count": len(disallowed),
                "sensitive_paths_found": sensitive_paths,
                "sitemaps": sitemaps,
            }
        else:
            return {"target": target, "status": "success", "found": False, "message": f"No robots.txt found (Status {response.status_code})"}
            
    except Exception as e:
        return {"status": "error", "message": str(e)}
