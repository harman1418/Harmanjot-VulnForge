from fastapi import APIRouter
import httpx

router = APIRouter()

@router.get("/")
def drupal_scanner(target: str):
    try:
        url = f"https://{target}" if not target.startswith("http") else target
        res = httpx.get(f"{url}/CHANGELOG.txt", verify=False, timeout=10, follow_redirects=True)
        is_drupal = "Drupal" in res.text or "drupal.org" in res.text
        
        if is_drupal:
            version = "Unknown"
            for line in res.text.splitlines()[:15]:
                if "Drupal" in line:
                    version = line.strip()
                    break
            return {"target": target, "status": "success", "detected": True, "version": version}
            
        return {"target": target, "status": "success", "detected": False}
    except Exception as e:
        return {"status": "error", "message": str(e)}
