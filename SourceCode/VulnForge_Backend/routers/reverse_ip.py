from fastapi import APIRouter
import httpx

router = APIRouter()

@router.get("/")
def reverse_ip_lookup(target: str):
    try:
        ip = target.replace("http://", "").replace("https://", "").split("/")[0]
        res = httpx.get(f"https://api.hackertarget.com/reverseiplookup/?q={ip}", timeout=15)
        
        if res.status_code == 200:
            domains = res.text.splitlines()
            if len(domains) == 1 and ("error" in domains[0].lower() or "api count exceeded" in domains[0].lower() or "quota" in domains[0].lower()):
                return {"target": target, "status": "error", "message": domains[0]}
            return {"target": target, "status": "success", "total": len(domains), "domains": domains[:100]}
        return {"target": target, "status": "error", "message": "Failed to fetch reverse IP data"}
    except Exception as e:
        return {"status": "error", "message": str(e)}
