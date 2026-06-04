from fastapi import APIRouter
import subprocess
import json

router = APIRouter()

@router.get("/")
def waf_detect(target: str):
    try:
        if not target.startswith("http"):
            url = f"https://{target}"
        else:
            url = target

        cmd = ["wafw00f", url, "-o", "-", "-f", "json"]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30
        )

        # Parse the JSON output from wafw00f
        try:
            data = json.loads(result.stdout)
            if isinstance(data, list) and len(data) > 0:
                entry = data[0]
                detected = entry.get("detected", False)
                firewall = entry.get("firewall", "None")
                manufacturer = entry.get("manufacturer", "Unknown")
                return {
                    "target": target,
                    "status": "success",
                    "detected": detected,
                    "waf_detected": detected,
                    "waf": firewall if detected else "None",
                    "waf_name": firewall if detected else "None",
                    "manufacturer": manufacturer if detected else "Unknown",
                }
            else:
                return {
                    "target": target,
                    "status": "success",
                    "detected": False,
                    "waf_detected": False,
                    "waf": "None",
                    "waf_name": "None",
                    "manufacturer": "Unknown",
                }
        except json.JSONDecodeError:
            # Fallback: parse raw text output
            out = result.stdout.lower()
            detected = "is behind" in out
            waf_name = "Unknown"
            if detected:
                for line in result.stdout.splitlines():
                    if "is behind" in line.lower():
                        parts = line.split("is behind")
                        if len(parts) > 1:
                            # Clean up ANSI color escapes
                            raw_waf = parts[1].strip().rstrip(".")
                            import re
                            cleaned = re.sub(r'\x1b\[[0-9;]*[a-zA-Z]', '', raw_waf)
                            cleaned = re.sub(r'\[\d+(?:;\d+)*[mGKH]', '', cleaned)
                            cleaned = cleaned.replace('■', '').strip()
                            waf_name = cleaned
            return {
                "target": target,
                "status": "success",
                "detected": detected,
                "waf_detected": detected,
                "waf": waf_name if detected else "None",
                "waf_name": waf_name if detected else "None",
            }

    except subprocess.TimeoutExpired:
        return {"status": "error", "message": "WAF scan timed out"}
    except FileNotFoundError:
        return {"status": "error", "message": "wafw00f is not installed on the server"}
    except Exception as e:
        return {"status": "error", "message": str(e)}
