from fastapi import APIRouter
import subprocess

router = APIRouter()

@router.get("/")
def dns_brute_force(target: str):
    try:
        url = target.replace("http://", "").replace("https://", "").split("/")[0]
        # Using gobuster dns mode
        cmd = ["gobuster", "dns", "-d", url, "-w", "/usr/share/wordlists/dirb/common.txt", "-q", "--no-error"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        
        subdomains = []
        for line in result.stdout.splitlines():
            if "Found:" in line:
                subdomains.append(line.replace("Found:", "").strip())
                
        return {"target": target, "status": "success", "total": len(subdomains), "subdomains": subdomains}
    except Exception as e:
        return {"status": "error", "message": str(e)}
