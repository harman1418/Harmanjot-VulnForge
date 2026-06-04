from fastapi import APIRouter
import subprocess

router = APIRouter()

@router.get("/")
def vhost_fuzzer(target: str):
    try:
        url = target.replace("http://", "").replace("https://", "").split("/")[0]
        # using gobuster vhost mode with reasonable settings
        cmd = [
            "gobuster", "vhost",
            "-u", f"https://{url}",
            "-w", "/usr/share/wordlists/dirb/common.txt",
            "-q",
            "--append-domain",
            "-t", "40",             # 40 threads (optimized for speed)
            "--timeout", "2s",      # 2s per-request timeout (highly optimized)
            "-k",                   # skip TLS
            "--no-error",           # suppress connection errors
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=90)
        
        # Check if gobuster itself failed to connect
        if result.returncode != 0 and result.stderr:
            err = result.stderr.strip()
            if "unable to connect" in err.lower() or "context deadline" in err.lower():
                return {"target": target, "status": "success", "total": 0, "vhosts": [], "note": "Target blocked or throttled VHost enumeration"}
        
        vhosts = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if "Found:" in line:
                vhosts.append(line.replace("Found:", "").strip())
            elif line and not line.startswith("Error"):
                # Some gobuster versions don't prefix with "Found:"
                vhosts.append(line)
                
        return {"target": target, "status": "success", "total": len(vhosts), "vhosts": vhosts}
    except subprocess.TimeoutExpired:
        return {"target": target, "status": "success", "total": 0, "vhosts": [], "note": "VHost scan timed out. Target may be throttling."}
    except Exception as e:
        return {"status": "error", "message": str(e)}
