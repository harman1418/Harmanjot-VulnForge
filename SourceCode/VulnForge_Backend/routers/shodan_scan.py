from fastapi import APIRouter
import httpx
import socket

router = APIRouter()

@router.get("/")
def shodan_lookup(target: str):
    try:
        host = target.replace("http://", "").replace("https://", "").split("/")[0]
        
        # Resolve domain to IP first
        try:
            ip = socket.gethostbyname(host)
        except socket.gaierror:
            return {"target": target, "status": "error", "message": f"Could not resolve {host} to an IP address"}

        # Use Shodan's free InternetDB API (No API key required!)
        res = httpx.get(f"https://internetdb.shodan.io/{ip}", timeout=15)
        
        if res.status_code == 200:
            data = res.json()
            return {
                "target": target,
                "status": "success",
                "ip": data.get("ip"),
                "org": "N/A (InternetDB)",
                "os": "N/A",
                "ports": data.get("ports", []),
                "vulns": data.get("vulns", []),
            }
        elif res.status_code == 404:
            return {"target": target, "status": "success", "message": "No data found in Shodan for this IP"}
        else:
            return {"target": target, "status": "error", "message": f"InternetDB error: {res.text}"}
    except Exception as e:
        return {"status": "error", "message": str(e)}
