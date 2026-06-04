from fastapi import APIRouter
import requests
import urllib3
urllib3.disable_warnings()
router = APIRouter()

TEST_ORIGINS = ["https://evil.com", "https://attacker.com", "null", "https://trusted.com"]

@router.get("/")
def cors_check(target: str):
    try:
        url = target if target.startswith("http") else f"https://{target}"
        results = []
        vulnerable = False
        for origin in TEST_ORIGINS:
            try:
                res = requests.get(url, headers={"Origin": origin}, timeout=10, verify=False)
                acao = res.headers.get("Access-Control-Allow-Origin", "")
                acac = res.headers.get("Access-Control-Allow-Credentials", "")
                is_vuln = (acao == "*" or acao == origin or (acao == "null" and origin == "null"))
                if is_vuln:
                    vulnerable = True
                results.append({
                    "origin_tested": origin,
                    "acao_header": acao or "Not set",
                    "acac_header": acac or "Not set",
                    "vulnerable": is_vuln,
                    "severity": "HIGH" if (is_vuln and acac.lower() == "true") else ("MEDIUM" if is_vuln else "NONE"),
                })
            except Exception as e:
                results.append({"origin_tested": origin, "error": str(e)})
        return {
            "status": "success",
            "target": target,
            "vulnerable": vulnerable,
            "risk_level": "HIGH" if vulnerable else "LOW",
            "results": results,
            "total_tested": len(TEST_ORIGINS),
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}
