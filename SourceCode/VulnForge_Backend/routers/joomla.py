from fastapi import APIRouter
import httpx

router = APIRouter()

@router.get("/")
def joomla_scanner(target: str):
    try:
        url = f"https://{target}" if not target.startswith("http") else target
        res = httpx.get(f"{url}/administrator/manifests/files/joomla.xml", verify=False, timeout=10, follow_redirects=True)
        is_joomla = "joomla" in res.text.lower()
        
        if is_joomla:
            import xml.etree.ElementTree as ET
            try:
                root = ET.fromstring(res.text)
                version = root.find("version").text
            except:
                version = "Unknown"
            return {"target": target, "status": "success", "detected": True, "version": version}
            
        return {"target": target, "status": "success", "detected": False}
    except Exception as e:
        return {"status": "error", "message": str(e)}
