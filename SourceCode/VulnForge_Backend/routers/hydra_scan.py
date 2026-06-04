from fastapi import APIRouter
import subprocess
import os
import re

router = APIRouter()

# Wordlist options with fallbacks
WORDLISTS = {
    "common": [
        "/usr/share/wordlists/metasploit/common_passwords.txt",    # 10k passwords
    ],
    "rockyou": [
        "/usr/share/wordlists/rockyou-75k.txt",                    # 59k passwords (SecLists rockyou-75)
        "/usr/share/wordlists/rockyou-10k.txt",                    # 10k passwords (SecLists top 10k)
        "/usr/share/wordlists/rockyou.txt",                        # full rockyou (if installed)
        "/usr/share/wordlists/metasploit/common_passwords.txt",    # fallback
    ],
}

def find_wordlist(name):
    """Find the first available wordlist for the given name."""
    candidates = WORDLISTS.get(name, WORDLISTS["common"])
    for path in candidates:
        if os.path.exists(path):
            return path
    return None


@router.get("/")
def hydra_scan(
    target: str,
    service: str = "ssh",
    username: str = "admin",
    wordlist: str = "common"
):
    try:
        wl = find_wordlist(wordlist)
        if not wl:
            return {
                "status": "error",
                "message": f"Wordlist '{wordlist}' not found on server. Available: common, rockyou"
            }

        # Pre-check: is the target port reachable?
        import socket
        port_map = {"ssh": 22, "ftp": 21, "http-get": 80, "https-get": 443, "smtp": 25, "telnet": 23, "mysql": 3306, "rdp": 3389}
        check_port = port_map.get(service, 22)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result_conn = sock.connect_ex((target, check_port))
            sock.close()
            if result_conn != 0:
                return {
                    "target": target,
                    "service": service,
                    "status": "error",
                    "message": f"Port {check_port} ({service}) is not open on {target}. Cannot brute force a closed port."
                }
        except socket.gaierror:
            return {"status": "error", "message": f"Cannot resolve hostname: {target}"}
        except Exception:
            pass  # Continue anyway if check fails

        # Count passwords for reporting
        try:
            with open(wl, 'r', errors='ignore') as f:
                pw_count = sum(1 for _ in f)
        except:
            pw_count = 0

        # Set threads and timeout based on wordlist size
        threads = "4"
        timeout = min(300, max(60, pw_count // 50))

        cmd = [
            "hydra",
            "-l", username,
            "-P", wl,
            "-t", threads,
            "-w", "5",                  # 5s max wait per connection
            "-W", "3",                  # 3s wait between connects
            "-f",                       # stop on first valid password
            "-o", "/tmp/hydra_output.txt",
            target,
            service,
        ]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )

        output = result.stdout + "\n" + result.stderr

        # Parse cracked credentials
        credentials = []
        for line in output.splitlines():
            # Hydra format: [22][ssh] host: 1.2.3.4   login: admin   password: pass123
            if "login:" in line.lower() and "password:" in line.lower():
                match = re.search(r'login:\s*(\S+)\s+password:\s*(\S+)', line, re.IGNORECASE)
                if match:
                    credentials.append({
                        "username": match.group(1),
                        "password": match.group(2),
                        "login": match.group(1),
                    })

        # Count attempts made
        attempts = 0
        for line in output.splitlines():
            if "[ATTEMPT]" in line or "login:" in line.lower():
                attempts += 1

        cracked = len(credentials) > 0

        return {
            "target": target,
            "service": service,
            "username": username,
            "status": "success",
            "cracked": cracked,
            "found": credentials,
            "credentials": credentials,
            "attempts_made": attempts if attempts > 0 else pw_count,
            "wordlist_used": os.path.basename(wl),
            "wordlist_size": pw_count,
        }

    except subprocess.TimeoutExpired:
        # Try to read partial results
        credentials = []
        try:
            if os.path.exists("/tmp/hydra_output.txt"):
                with open("/tmp/hydra_output.txt", "r") as f:
                    for line in f:
                        if "login:" in line.lower() and "password:" in line.lower():
                            match = re.search(r'login:\s*(\S+)\s+password:\s*(\S+)', line, re.IGNORECASE)
                            if match:
                                credentials.append({
                                    "username": match.group(1),
                                    "password": match.group(2),
                                    "login": match.group(1),
                                })
        except:
            pass

        if credentials:
            return {
                "target": target,
                "service": service,
                "status": "success",
                "cracked": True,
                "found": credentials,
                "credentials": credentials,
                "note": "Scan timed out but credentials were found",
            }

        return {"status": "error", "message": "Scan timed out. Try 'common' wordlist for faster results."}
    except FileNotFoundError:
        return {"status": "error", "message": "hydra is not installed on the server"}
    except Exception as e:
        return {"status": "error", "message": str(e)}
