from fastapi import APIRouter
import subprocess
import json
import os
import uuid

router = APIRouter()

@router.get("/")
def subdomain_takeover(target: str):
    try:
        clean = target.replace("https://","").replace("http://","").split("/")[0]
        
        # 1. Run subfinder to gather subdomains
        result = subprocess.run(["subfinder", "-d", clean, "-silent"], capture_output=True, text=True, timeout=60)
        subdomains = [s.strip() for s in result.stdout.strip().split("\n") if s.strip()]
        
        if not subdomains:
            return {"status": "success", "target": clean, "subdomains_checked": 0, "vulnerable_count": 0, "vulnerable": [], "risk_level": "LOW"}

        # 2. Save subdomains to a temporary file for subzy
        uid = str(uuid.uuid4())
        targets_file = f"/tmp/subzy_targets_{uid}.txt"
        output_file = f"/tmp/subzy_out_{uid}.json"
        
        with open(targets_file, "w") as f:
            f.write("\n".join(subdomains))

        # 3. Run subzy
        # Using --vuln to only save vulnerable results to the JSON file
        subprocess.run(["subzy", "run", "--targets", targets_file, "--vuln", "--hide_fails", "--output", output_file], capture_output=True, text=True, timeout=120)

        # 4. Parse the results
        vulnerable = []
        if os.path.exists(output_file):
            try:
                with open(output_file, "r") as f:
                    data = json.load(f)
                    if data:
                        # Map subzy's output format to our expected format
                        for item in data:
                            vulnerable.append({
                                "subdomain": item.get("subdomain", ""),
                                "service": item.get("engine", "Unknown"),
                                "vulnerable": True
                            })
            except Exception:
                pass
            os.remove(output_file)
            
        if os.path.exists(targets_file):
            os.remove(targets_file)

        return {
            "status": "success",
            "target": clean,
            "subdomains_checked": len(subdomains),
            "vulnerable_count": len(vulnerable),
            "vulnerable": vulnerable,
            "risk_level": "CRITICAL" if vulnerable else "LOW",
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}
