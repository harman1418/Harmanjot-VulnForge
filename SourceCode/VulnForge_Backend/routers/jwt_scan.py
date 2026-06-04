from fastapi import APIRouter
import requests, re, base64, json
import urllib3
urllib3.disable_warnings()
router = APIRouter()

@router.get("/")
def jwt_scan(target: str):
    try:
        url = target if target.startswith("http") else f"https://{target}"
        findings = []
        res = requests.get(url, timeout=10, verify=False)
        content = res.text
        jwt_pattern = r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'
        tokens = re.findall(jwt_pattern, content)
        for token in set(tokens[:10]):
            try:
                parts = token.split(".")
                header_b64 = parts[0] + "=" * (-len(parts[0]) % 4)
                header = json.loads(base64.urlsafe_b64decode(header_b64))
                payload_b64 = parts[1] + "=" * (-len(parts[1]) % 4)
                payload = json.loads(base64.urlsafe_b64decode(payload_b64))
                issues = []
                alg = header.get("alg", "")
                if alg.upper() == "NONE":
                    issues.append({"severity": "CRITICAL", "issue": "Algorithm is none - token not verified"})
                if alg.upper() in ["HS256", "HS384", "HS512"]:
                    issues.append({"severity": "MEDIUM", "issue": "Symmetric algorithm - weak secret possible"})
                if "exp" not in payload:
                    issues.append({"severity": "MEDIUM", "issue": "No expiration claim - token never expires"})
                findings.append({
                    "token_preview": token[:40] + "...",
                    "header": header,
                    "payload_keys": list(payload.keys()),
                    "algorithm": alg,
                    "issues": issues,
                    "severity": issues[0]["severity"] if issues else "INFO",
                })
            except:
                pass
        auth_headers = {h: res.headers.get(h, "Not present") for h in ["Authorization", "X-Auth-Token", "X-API-Key"]}
        return {
            "status": "success",
            "target": target,
            "tokens_found": len(findings),
            "findings": findings,
            "auth_headers": auth_headers,
            "risk_level": "HIGH" if any(f["severity"] in ["CRITICAL","HIGH"] for f in findings) else ("MEDIUM" if findings else "LOW"),
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}
