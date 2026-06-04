from fastapi import APIRouter
import subprocess

router = APIRouter()

@router.get("/")
def email_harvester(target: str):
    try:
        url = target.replace("http://", "").replace("https://", "").split("/")[0]
        cmd = ["theHarvester", "-d", url, "-l", "50", "-b", "duckduckgo,crtsh"]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=500)
            emails = []
            hosts = []
            for line in result.stdout.splitlines():
                if "@" in line and url in line:
                    emails.append(line.strip())
                elif "Host:" in line:
                    hosts.append(line.split("Host:")[1].strip())
            return {"target": target, "status": "success", "emails": list(set(emails)), "hosts": list(set(hosts))}
        except FileNotFoundError:
            return {"target": target, "status": "error", "message": "theHarvester tool is not installed on the server."}
    except Exception as e:
        return {"status": "error", "message": str(e)}
