from fastapi import APIRouter
import subprocess
import os

router = APIRouter()

@router.get("/")
def gobuster_scan(target: str, wordlist: str = "common"):
    try:
        if not target.startswith("http"):
            url = f"https://{target}"
        else:
            url = target

        # Wordlist Mapping — Optimized for speed vs coverage
        # common: ~4,600 words (True fast scan)
        # medium: ~30,000 words
        # big/large: ~62,000 words
        
        if wordlist == "common":
            wl = "/usr/share/wordlists/dirb/common.txt"
            if not os.path.exists(wl):
                wl = "/usr/share/wordlists/seclists/raft-medium-dirs.txt"
            scan_timeout = 180 # 3 minutes
        elif wordlist == "medium":
            wl = "/usr/share/wordlists/seclists/raft-medium-dirs.txt"
            if not os.path.exists(wl):
                wl = "/usr/share/wordlists/dirb/common.txt"
            scan_timeout = 300 # 5 minutes
        elif wordlist == "big" or wordlist == "large":
            wl = "/usr/share/wordlists/seclists/raft-large-dirs.txt"
            if not os.path.exists(wl):
                wl = "/usr/share/wordlists/dirb/big.txt"
            scan_timeout = 600 # 10 minutes
        else:
            wl = "/usr/share/wordlists/dirb/common.txt"
            scan_timeout = 180

        output_file = f"/tmp/gobuster_{target.replace('/', '_').replace(':', '_')}.txt"

        cmd = [
            "gobuster", "dir",
            "-u", url,
            "-w", wl,
            "-t", "40",              # Increased to 40 threads for faster results
            "--timeout", "2s",       # 2s per HTTP request timeout (highly optimized)
            "--no-progress",
            "-q",                    # quiet mode
            "-k",                    # skip TLS cert verification
            "--no-error",            # suppress connection errors from output
            "-s", "200,204,301,302,307,401,403",  # status codes to match
            "-b", "",                    # disable default blacklist
            "-o", output_file
        ]

        # Use a slightly larger timeout for the subprocess to allow for parsing
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=scan_timeout
        )

        findings = []
        if os.path.exists(output_file):
            with open(output_file, "r") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("Error"):
                        findings.append(line)
            os.remove(output_file)

        if not findings and result.stdout:
            for line in result.stdout.splitlines():
                line = line.strip()
                if line and not line.startswith("Error"):
                    findings.append(line)

        return {
            "target": target,
            "status": "success",
            "wordlist": wordlist,
            "total_found": len(findings),
            "findings": findings
        }

    except subprocess.TimeoutExpired:
        # Partial result recovery on timeout
        findings = []
        output_file = f"/tmp/gobuster_{target.replace('/', '_').replace(':', '_')}.txt"
        if os.path.exists(output_file):
            with open(output_file, "r") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("Error"):
                        findings.append(line)
            os.remove(output_file)

        if findings:
            return {
                "target": target,
                "status": "success",
                "wordlist": wordlist,
                "total_found": len(findings),
                "findings": findings,
                "note": "Scan timed out but partial results were recovered. Try 'common' wordlist for faster results."
            }

        return {"status": "error", "message": "Scan timed out. The target might be slow or blocking requests. Try a smaller wordlist."}
    except Exception as e:
        return {"status": "error", "message": str(e)}
