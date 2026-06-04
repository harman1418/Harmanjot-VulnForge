from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Request
from fastapi.responses import FileResponse
from utils.database import scans_collection
from utils.email import send_scan_complete_email
import asyncio
import subprocess
import json
import os
import xml.etree.ElementTree as ET
from datetime import datetime
import requests as http_requests
from dotenv import load_dotenv
import uuid
import jwt
import re
from urllib.parse import urlparse

# ── IMPORTS FOR ALL 12 NEW TOOLS ──────────────────────────────────────────────
from routers.robots_txt import robots_analyzer
from routers.cookie_check import cookie_security_checker
from routers.clickjacking import clickjacking_tester
from routers.dns_brute import dns_brute_force
from routers.vhost import vhost_fuzzer
from routers.api_scan import api_scanner
from routers.drupal import drupal_scanner
from routers.joomla import joomla_scanner
from routers.email_harvester import email_harvester
from routers.shodan_scan import shodan_lookup
from routers.reverse_ip import reverse_ip_lookup
from routers.tech_detect import tech_detector
from routers.report_generator import generate_report
from routers.subdomain_takeover import subdomain_takeover
# ──────────────────────────────────────────────────────────────────────────────

load_dotenv()

router = APIRouter()

# ── Active scan tracking ──────────────────────────────────────────────────────
# {target: {"status": "running"|"complete"|"error", "scan_type": str,
#           "logs": [...], "phase": int, "scan_id": str|None, "cancel": bool}}
active_scans = {}


CF_ACCOUNT_ID = os.getenv("CF_ACCOUNT_ID")
CF_API_TOKEN  = os.getenv("CF_API_TOKEN")
JWT_SECRET    = os.getenv("SECRET_KEY", "vulnforge_secret_2024")
JWT_ALGORITHM = "HS256"


def clean_target_domain(target: str) -> str:
    target = target.strip().lower()
    if not target:
        return target
    if "://" not in target:
        parsed = urlparse(f"http://{target}")
    else:
        parsed = urlparse(target)
    host = parsed.netloc or parsed.path
    if ":" in host:
        host = host.split(":")[0]
    return host.strip().strip("/")


# ─── Tool Runners ─────────────────────────────────────────────────────────────

def run_portscan(target, scan_type="medium"):
    try:
        if scan_type == "light":
            cmd = ["nmap", "-T4", "-sV", "--top-ports", "1000", "--open", "-oX", "-", target]
            timeout = 300
        elif scan_type == "medium":
            cmd = ["nmap", "-T4", "-sV", "-sC", "--top-ports", "5000", "--open", "-oX", "-", target]
            timeout = 600
        else:
            cmd = ["nmap", "-T4", "-sV", "-sC", "-A", "-p-", "--open", "-oX", "-", target]
            timeout = 1800

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        ports = []
        os_info = ""
        try:
            root = ET.fromstring(result.stdout)
            for host in root.findall('host'):
                os_match = host.find('./os/osmatch')
                if os_match is not None:
                    os_info = os_match.get('name', '')
                for port in host.findall('./ports/port'):
                    state = port.find('state')
                    service = port.find('service')
                    if state is not None and state.get('state') == 'open':
                        ports.append({
                            "port": port.get('portid'),
                            "protocol": port.get('protocol'),
                            "service": service.get('name') if service is not None else 'unknown',
                            "version": (service.get('product', '') + ' ' + service.get('version', '')).strip() if service is not None else '',
                            "extrainfo": service.get('extrainfo', '') if service is not None else '',
                        })
        except:
            pass
        return {"status": "success", "total": len(ports), "ports": ports, "os": os_info}
    except subprocess.TimeoutExpired:
        return {"status": "timeout", "total": 0, "ports": [], "os": ""}
    except Exception as e:
        return {"status": "error", "message": str(e)}


def run_subdomain(target, scan_type="medium"):
    try:
        if scan_type == "light":
            cmd = ["subfinder", "-d", target, "-silent", "-timeout", "30"]
            timeout = 90
        elif scan_type == "medium":
            cmd = ["subfinder", "-d", target, "-silent", "-all", "-timeout", "60"]
            timeout = 180
        else:
            cmd = ["subfinder", "-d", target, "-silent", "-all", "-recursive", "-timeout", "120"]
            timeout = 360

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        subdomains = [l.strip() for l in result.stdout.splitlines() if l.strip()]

        if scan_type == "deep":
            try:
                dns_result = subprocess.run(
                    ["gobuster", "dns", "-d", target, "-w", "/usr/share/wordlists/dirb/common.txt", "-q", "--no-error"],
                    capture_output=True, text=True, timeout=300
                )
                for line in dns_result.stdout.splitlines():
                    if "Found:" in line:
                        sub = line.replace("Found:", "").strip()
                        if sub and sub not in subdomains:
                            subdomains.append(sub)
            except:
                pass

        return {"status": "success", "total": len(subdomains), "subdomains": list(set(subdomains))}
    except Exception as e:
        return {"status": "error", "message": str(e)}


def run_whois(target):
    try:
        import whois
        w = whois.whois(target)
        return {
            "status": "success",
            "registrar": str(w.registrar),
            "creation_date": str(w.creation_date),
            "expiration_date": str(w.expiration_date),
            "org": str(w.org),
            "country": str(w.country),
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}


def run_dns(target):
    try:
        import dns.resolver
        records = {}
        for rtype in ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME']:
            try:
                answers = dns.resolver.resolve(target, rtype)
                records[rtype] = [str(r) for r in answers]
            except:
                pass
        return {"status": "success", "records": records}
    except Exception as e:
        return {"status": "error", "message": str(e)}


def run_headers(target, scan_type="medium"):
    try:
        import httpx
        import builtwith
        url = f"https://{target}" if not target.startswith("http") else target
        response = httpx.get(url, follow_redirects=True, timeout=30, verify=False)
        headers = dict(response.headers)
        try:
            technologies = builtwith.parse(url)
        except:
            technologies = {}
        security_headers = {
            "X-Frame-Options": headers.get("x-frame-options", "NOT SET"),
            "X-Content-Type-Options": headers.get("x-content-type-options", "NOT SET"),
            "Strict-Transport-Security": headers.get("strict-transport-security", "NOT SET"),
            "Content-Security-Policy": headers.get("content-security-policy", "NOT SET"),
            "X-XSS-Protection": headers.get("x-xss-protection", "NOT SET"),
            "Referrer-Policy": headers.get("referrer-policy", "NOT SET"),
            "Permissions-Policy": headers.get("permissions-policy", "NOT SET"),
        }
        return {
            "status": "success",
            "server": headers.get("server", "Unknown"),
            "technologies": technologies,
            "security_headers": security_headers,
            "status_code": response.status_code,
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}


def run_waf(target):
    try:
        url = f"https://{target}" if not target.startswith("http") else target
        result = subprocess.run(["wafw00f", url, "-a"], capture_output=True, text=True, timeout=60)
        output = result.stdout
        detected = "is behind" in output.lower()
        waf_name = "None detected"
        for line in output.splitlines():
            if "is behind" in line.lower():
                waf_name = line.strip()
        return {"status": "success", "detected": detected, "waf": waf_name}
    except Exception as e:
        return {"status": "error", "message": str(e)}


def run_ssl(target, scan_type="medium"):
    try:
        host = target.replace("https://", "").replace("http://", "").split("/")[0]
        cmd = ["sslyze", "--json_out=-", host] if scan_type == "light" else ["sslyze", "--json_out=-", "--regular", host]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        try:
            data = json.loads(result.stdout)
            scan = data["server_scan_results"][0]["scan_result"]
            return {
                "status": "success",
                "tls_1_0": scan.get("tls_1_0_cipher_suites", {}).get("status", ""),
                "tls_1_1": scan.get("tls_1_1_cipher_suites", {}).get("status", ""),
                "tls_1_2": scan.get("tls_1_2_cipher_suites", {}).get("status", ""),
                "tls_1_3": scan.get("tls_1_3_cipher_suites", {}).get("status", ""),
            }
        except:
            return {"status": "success", "raw": result.stdout[:300]}
    except Exception as e:
        return {"status": "error", "message": str(e)}


def run_nuclei(target, scan_type="medium"):
    try:
        url = f"https://{target}" if not target.startswith("http") else target
        if scan_type == "medium":
            cmd = ["nuclei", "-u", url, "-severity", "critical,high", "-json", "-silent", "-timeout", "10", "-rate-limit", "50"]
            timeout = 300
        else:
            cmd = ["nuclei", "-u", url, "-severity", "critical,high,medium", "-json", "-silent", "-timeout", "15", "-rate-limit", "100"]
            timeout = 600
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        findings = []
        for line in result.stdout.splitlines():
            try:
                f = json.loads(line)
                findings.append({
                    "template": f.get("template-id", ""),
                    "name": f.get("info", {}).get("name", ""),
                    "severity": f.get("info", {}).get("severity", ""),
                    "description": f.get("info", {}).get("description", "")[:200],
                    "matched_at": f.get("matched-at", ""),
                })
            except:
                pass
        return {"status": "success", "total": len(findings), "findings": findings}
    except Exception as e:
        return {"status": "error", "message": str(e)}


def run_gobuster(target, scan_type="medium"):
    try:
        url = f"https://{target}" if not target.startswith("http") else target
        wordlist = "/usr/share/wordlists/dirb/common.txt" if scan_type in ["light", "medium"] else "/usr/share/wordlists/dirb/big.txt"
        timeout = 90 if scan_type in ["light", "medium"] else 180
        output_file = f"/tmp/gobuster_full_{target.replace('/', '_').replace(':', '_')}.txt"
        result = subprocess.run(
            ["gobuster", "dir", "-u", url, "-w", wordlist, "-t", "40", "--timeout", "2s",
             "-q", "--no-progress", "--no-error", "-k", "-s", "200,204,301,302,307,401,403",
             "-b", "", "-o", output_file],
            capture_output=True, text=True, timeout=timeout
        )
        findings = []
        # Read from output file (more reliable) 
        import os
        if os.path.exists(output_file):
            with open(output_file, "r") as f:
                findings = [l.strip() for l in f if l.strip() and not l.startswith("Error")]
            os.remove(output_file)
        # Fallback to stdout
        if not findings:
            findings = [l.strip() for l in result.stdout.splitlines() if l.strip() and not l.startswith("Error")]
        return {"status": "success", "total": len(findings), "findings": findings[:50]}
    except subprocess.TimeoutExpired:
        findings = []
        import os
        output_file = f"/tmp/gobuster_full_{target.replace('/', '_').replace(':', '_')}.txt"
        if os.path.exists(output_file):
            with open(output_file, "r") as f:
                findings = [l.strip() for l in f if l.strip() and not l.startswith("Error")]
            os.remove(output_file)
        if findings:
            return {"status": "success", "total": len(findings), "findings": findings[:50], "note": "Partial results (timed out)"}
        return {"status": "error", "message": "Scan timed out"}
    except Exception as e:
        return {"status": "error", "message": str(e)}


def run_wpscan(target):
    try:
        url = f"https://{target}" if not target.startswith("http") else target
        result = subprocess.run(
            ["wpscan", "--url", url, "--format", "json", "--no-update", "--enumerate", "p,t,u"],
            capture_output=True, text=True, timeout=300
        )
        try:
            data = json.loads(result.stdout)
            return {
                "status": "success",
                "is_wordpress": True,
                "vulnerabilities": data.get("vulnerabilities", []),
                "plugins": list(data.get("plugins", {}).keys())[:10],
            }
        except:
            return {"status": "success", "is_wordpress": "wordpress" in result.stdout.lower()}
    except Exception as e:
        return {"status": "error", "message": str(e)}


def run_nikto(target):
    try:
        url = f"https://{target}" if not target.startswith("http") else target
        result = subprocess.run(
            ["nikto", "-h", url, "-nointeractive", "-maxtime", "300"],
            capture_output=True, text=True, timeout=360
        )
        findings = [l.strip() for l in result.stdout.splitlines() if "+ " in l]
        return {"status": "success", "total": len(findings), "findings": findings[:20]}
    except Exception as e:
        return {"status": "error", "message": str(e)}


def run_sqli(target):
    try:
        url = f"https://{target}" if not target.startswith("http") else target
        result = subprocess.run(
            ["sqlmap", "-u", url, "--batch", "--level=2", "--risk=2", "--forms", "--crawl=3", "--random-agent", "-v", "0"],
            capture_output=True, text=True, timeout=600
        )
        vulnerable = "injectable" in result.stdout.lower() or "sqlmap identified" in result.stdout.lower()
        return {"status": "success", "vulnerable": vulnerable}
    except Exception as e:
        return {"status": "error", "message": str(e)}


# ─── AI Analysis via Cloudflare ───────────────────────────────────────────────

def normalize_cvss(analysis):
    """Ensure risk_level always matches the CVSS score per CVSS v3.1 ranges."""
    try:
        score = float(analysis.get("security_score", 0))
        if score >= 9.0:
            analysis["risk_level"] = "CRITICAL"
        elif score >= 7.0:
            analysis["risk_level"] = "HIGH"
        elif score >= 4.0:
            analysis["risk_level"] = "MEDIUM"
        elif score > 0:
            analysis["risk_level"] = "LOW"
        else:
            analysis["risk_level"] = "LOW"
    except (ValueError, TypeError):
        pass
    return analysis

def analyze_with_ai(target, scan_results, scan_type="medium"):
    try:
        limited = {
            "portscan": {
                "total": scan_results.get("portscan", {}).get("total", 0),
                "os": scan_results.get("portscan", {}).get("os", ""),
                "ports": scan_results.get("portscan", {}).get("ports", [])[:20],
            },
            "shodan": {
                "ip": scan_results.get("shodan_scan", {}).get("ip", ""),
                "ports": scan_results.get("shodan_scan", {}).get("ports", []),
                "cves": scan_results.get("shodan_scan", {}).get("vulns", [])[:5]
            },

            "subdomain": {
                "total": scan_results.get("subdomain", {}).get("total", 0),
                "sample": scan_results.get("subdomain", {}).get("subdomains", [])[:10],
            },
            "headers": {
                "server": scan_results.get("headers", {}).get("server", ""),
                "security_headers": scan_results.get("headers", {}).get("security_headers", {}),
                "technologies": scan_results.get("headers", {}).get("technologies", {}),
            },
            "waf": {
                "detected": scan_results.get("waf", {}).get("detected", False),
                "waf": scan_results.get("waf", {}).get("waf", ""),
            },
            "nuclei": {
                "total": scan_results.get("nuclei", {}).get("total", 0),
                "findings": scan_results.get("nuclei", {}).get("findings", [])[:5],
            },
        }

        prompt = f"""You are an elite penetration tester. Provide a comprehensive JSON analysis of this {scan_type} scan for {target}.

Scan Data:
{json.dumps(limited, indent=2)}

STRICT RULES:
1. DO NOT report ports 80 (HTTP) or 443 (HTTPS) as vulnerabilities. These are standard web ports.
2. DO NOT flag standard cloud infrastructure (like Vercel, Cloudflare, AWS) as unsecured simply for existing.
3. Missing security headers (like X-Frame-Options, CSP, HSTS) MUST be classified as LOW or MEDIUM risk, NEVER CRITICAL or HIGH.
4. CRITICAL and HIGH findings MUST be reserved ONLY for explicitly exploitable vulnerabilities (e.g., SQLi, XSS, exposed sensitive data, or known CVEs).
5. Calculate a "security_score" as a CVSS-style float from 0.0 to 10.0 representing overall risk severity. Higher means MORE risk. Use CVSS v3.1 scoring: CRITICAL findings contribute 9.0-10.0, HIGH: 7.0-8.9, MEDIUM: 4.0-6.9, LOW: 0.1-3.9. If multiple findings exist, use the highest severity score and adjust upward slightly for quantity. A target with no findings should score 0.0.
6. DO NOT claim that security headers are "missing" if they are present in the Scan Data with valid non-"NOT SET" values (e.g., if X-Frame-Options is "DENY", it is NOT missing, it is set). Only flag them if they have "NOT SET" or "Missing" as their value.
7. If a security header is set but has weak/insecure directives (such as 'unsafe-inline' or 'unsafe-eval' in Content-Security-Policy), describe it as a "weak/loose configuration" rather than "missing".
8. If the scan shows no high or critical CVE findings, and no active exploits, do not exaggerate risks. The overall risk_level MUST be LOW or MEDIUM, and security_score MUST be under 4.0.

You MUST respond with ONLY valid JSON. Do not include markdown blocks, greetings, or any other text.
The JSON must strictly match this schema:
{{
  "risk_level": "CRITICAL, HIGH, MEDIUM, or LOW",
  "executive_summary": "A highly detailed 4-5 sentence professional summary of the target's security posture, emphasizing the business impact of the discovered vulnerabilities.",
  "critical_findings": [
    {{
      "title": "Vulnerability Name",
      "description": "Technical description of the issue and its potential impact.",
      "severity": "CRITICAL, HIGH, MEDIUM, or LOW",
      "evidence": "Data from the scan proving the vulnerability exists."
    }}
  ],
  "attack_recommendations": [
    {{
      "tool": "sqlmap, wpscan, nuclei, gobuster, or hydra",
      "target": "Exact URL, endpoint, or IP to attack",
      "reason": "Why this specific attack vector is viable based on the findings",
      "priority": "HIGH, MEDIUM, or LOW"
    }}
  ],
  "remediation_steps": [
    {{
      "issue": "Specific security vulnerability",
      "fix": "Detailed technical remediation techniques and configuration changes required.",
      "priority": "HIGH, MEDIUM, or LOW"
    }}
  ],
  "security_score": 6.5
}}"""

        response = http_requests.post(
            f"https://api.cloudflare.com/client/v4/accounts/{CF_ACCOUNT_ID}/ai/run/@cf/meta/llama-3.1-8b-instruct",
            headers={"Authorization": f"Bearer {CF_API_TOKEN}", "Content-Type": "application/json"},
            json={"messages": [{"role": "user", "content": prompt}], "max_tokens": 4000},
            timeout=60
        )

        result = response.json()
        text = result.get("result", {}).get("response", "").strip()
        text = text.replace("```json", "").replace("```", "").strip()

        start = text.find('{')
        end = text.rfind('}') + 1
        if start >= 0 and end > start:
            text = text[start:end]

        # Fix common LLM JSON issues
        text = re.sub(r',\s*}', '}', text)   # trailing comma before }
        text = re.sub(r',\s*]', ']', text)   # trailing comma before ]
        text = re.sub(r'[\x00-\x1f]', ' ', text)  # control characters
        text = text.replace('\n', ' ').replace('\r', ' ')  # newlines in strings

        # Try parsing as-is first
        try:
            return normalize_cvss(json.loads(text))
        except json.JSONDecodeError:
            pass

        # Try fixing unbalanced braces/brackets
        open_braces = text.count('{') - text.count('}')
        open_brackets = text.count('[') - text.count(']')
        if open_braces > 0:
            text += '}' * open_braces
        if open_brackets > 0:
            text += ']' * open_brackets
            # Re-close any braces that were before unclosed brackets
            text = re.sub(r',\s*}', '}', text)
            text = re.sub(r',\s*]', ']', text)

        try:
            return normalize_cvss(json.loads(text))
        except json.JSONDecodeError:
            pass

        # Last resort: try to extract key fields manually via regex
        try:
            risk_match = re.search(r'"risk_level"\s*:\s*"(CRITICAL|HIGH|MEDIUM|LOW)"', text)
            summary_match = re.search(r'"executive_summary"\s*:\s*"([^"]{10,500})"', text)
            score_match = re.search(r'"security_score"\s*:\s*([\d.]+)', text)

            if risk_match or summary_match:
                # Extract critical_findings array if possible
                findings = []
                findings_pattern = re.finditer(r'"title"\s*:\s*"([^"]+)".*?"description"\s*:\s*"([^"]+)".*?"severity"\s*:\s*"([^"]+)"', text)
                for fm in findings_pattern:
                    findings.append({
                        "title": fm.group(1),
                        "description": fm.group(2),
                        "severity": fm.group(3),
                        "evidence": ""
                    })

                # Extract remediation steps
                rems = []
                rems_pattern = re.finditer(r'"issue"\s*:\s*"([^"]+)".*?"fix"\s*:\s*"([^"]+)".*?"priority"\s*:\s*"([^"]+)"', text)
                for rm in rems_pattern:
                    rems.append({
                        "issue": rm.group(1),
                        "fix": rm.group(2),
                        "priority": rm.group(3)
                    })

                return normalize_cvss({
                    "risk_level": risk_match.group(1) if risk_match else "MEDIUM",
                    "executive_summary": summary_match.group(1) if summary_match else f"Scan completed for {target}. Manual review recommended.",
                    "critical_findings": findings,
                    "attack_recommendations": [],
                    "remediation_steps": rems,
                    "security_score": round(float(score_match.group(1)), 1) if score_match else 5.0
                })
        except:
            pass

        # Complete fallback
        return normalize_cvss({
            "risk_level": "MEDIUM",
            "executive_summary": f"Scan completed for {target}. Manual review of findings recommended. (AI response could not be parsed).",
            "critical_findings": [],
            "attack_recommendations": [],
            "remediation_steps": [],
            "security_score": 5.0
        })

    except Exception as e:
        return {
            "risk_level": "UNKNOWN",
            "executive_summary": f"AI analysis failed: {str(e)}",
            "critical_findings": [],
            "attack_recommendations": [],
            "remediation_steps": [],
            "security_score": 0.0
        }


def execute_ai_attacks(target, recommendations, scan_type="deep"):
    attack_results = []
    max_attacks = 2 if scan_type == "medium" else 4

    for rec in recommendations[:max_attacks]:
        tool = rec.get("tool", "")
        attack_target = rec.get("target", target)
        result = None

        if tool == "wpscan":
            result = run_wpscan(attack_target)
        elif tool == "nuclei":
            result = run_nuclei(attack_target, scan_type)
        elif tool == "gobuster":
            result = run_gobuster(attack_target, scan_type)
        elif tool == "sqlmap":
            result = run_sqli(attack_target)

        if result:
            attack_results.append({
                "tool": tool,
                "target": attack_target,
                "reason": rec.get("reason", ""),
                "priority": rec.get("priority", "MEDIUM"),
                "result": result
            })

    return attack_results


# ─── WebSocket Full Scan ──────────────────────────────────────────────────────

@router.get("/active/{target:path}")
async def get_active_scan(target: str, request: Request):
    """Check if a scan is active for a target — used for reconnect"""
    target = clean_target_domain(target)
    scan = active_scans.get(target)
    if not scan:
        return {"status": "none"}
    return {
        "status": scan["status"],
        "scan_type": scan.get("scan_type", "medium"),
        "phase": scan.get("phase", 0),
        "logs": scan.get("logs", [])[-50:],  # last 50 logs
        "scan_id": scan.get("scan_id"),
    }


@router.delete("/stop/{target:path}")
async def stop_scan(target: str):
    """Stop an active scan by killing the subprocess"""
    target = clean_target_domain(target)
    import signal, os
    if target not in active_scans:
        return {"status": "not_found", "message": "No active scan for this target"}
    
    active_scans[target]["cancel"] = True
    active_scans[target]["status"] = "cancelled"
    
    # Kill subprocess if running
    pid = active_scans.get(target, {}).get("pid")
    if pid:
        try:
            os.killpg(os.getpgid(pid), signal.SIGTERM)
        except Exception as e:
            print(f"Kill error: {e}")
    
    return {"status": "success", "message": f"Scan stopped for {target}"}


@router.websocket("/ws/{scan_type}/{target:path}")
async def full_scan_ws(websocket: WebSocket, target: str, scan_type: str = "medium", token: str = None):
    target = clean_target_domain(target)
    await websocket.accept()

    if scan_type not in ["light", "medium", "deep"]:
        scan_type = "medium"

    # Extract user_id from JWT token (query param OR HttpOnly cookie)
    user_id = "anonymous"
    user_email = "anonymous"
    # Try query param first, then fall back to HttpOnly cookie
    ws_token = token
    if not ws_token or ws_token in ["cookie_session", "null", "undefined"]:
        cookie_val = websocket.cookies.get("access_token", "")
        if cookie_val:
            cookie_val = cookie_val.strip().strip('"')
            if cookie_val.startswith("Bearer "):
                ws_token = cookie_val.split(" ", 1)[1]
    if ws_token:
        try:
            payload = jwt.decode(ws_token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
            user_id = payload.get("user_id", "anonymous")
            user_email = payload.get("email", "anonymous")
        except:
            pass

    # Prevent concurrent scans for the same target to avoid spam
    if target in active_scans and active_scans[target].get("status") == "running":
        existing_scan = active_scans[target]
        # Reconnect logic: register the new websocket and wait for scan completion/disconnect
        # Ensure event is present
        event = existing_scan.setdefault("event", asyncio.Event())

        # Add this websocket to the active scan's list of websockets
        if "websockets" not in existing_scan:
            existing_scan["websockets"] = []
        existing_scan["websockets"].append(websocket)

        # Wait for either client disconnect or scan completion event
        async def wait_client_disconnect():
            try:
                while True:
                    await websocket.receive_text()
            except Exception:
                pass

        disconnect_task = asyncio.create_task(wait_client_disconnect())
        event_task = asyncio.create_task(event.wait())

        try:
            done, pending = await asyncio.wait(
                [disconnect_task, event_task],
                return_when=asyncio.FIRST_COMPLETED
            )
        finally:
            # Clean up tasks
            disconnect_task.cancel()
            event_task.cancel()
            
            # Remove websocket from websockets list
            if target in active_scans and "websockets" in active_scans[target]:
                if websocket in active_scans[target]["websockets"]:
                    active_scans[target]["websockets"].remove(websocket)
            try:
                await websocket.close()
            except Exception:
                pass
        return

    # Register active scan
    active_scans[target] = {
        "status": "running",
        "scan_type": scan_type,
        "phase": 1,
        "logs": [],
        "scan_id": None,
        "cancel": False,
        "user_id": user_id,
        "pid": None,  # track subprocess PID for killing
        "websockets": [websocket],
        "event": asyncio.Event(),
    }

    async def send(phase, tool, status, data=None):
        msg = {
            "phase": phase, "tool": tool, "status": status,
            "data": data, "scan_type": scan_type,
            "timestamp": datetime.now().isoformat()
        }
        # Update active scan tracker
        if target in active_scans:
            active_scans[target]["phase"] = phase
            active_scans[target]["logs"].append({
                "phase": phase, "tool": tool, "status": status,
                "timestamp": msg["timestamp"],
                "data": data if status in ("done", "complete", "error") else None,
            })
            # Send to all connected websockets
            websockets = list(active_scans[target].get("websockets", []))
            for ws in websockets:
                try:
                    await ws.send_json(msg)
                except Exception:
                    if ws in active_scans[target]["websockets"]:
                        active_scans[target]["websockets"].remove(ws)

    scan_results = {}

    try:
        # ── Check for stop signal ──────────────────────────────────────
        async def check_cancel():
            if active_scans.get(target, {}).get("cancel", False):
                if target in active_scans:
                    active_scans[target]["status"] = "cancelled"
                    if "event" in active_scans[target]:
                        active_scans[target]["event"].set()
                await send(0, "VulnForge", "cancelled", {"message": "Scan stopped by user"})
                return True
            return False

        await check_cancel()
        await send(1, "Port Scanner", "running")
        scan_results["portscan"] = await asyncio.get_event_loop().run_in_executor(None, run_portscan, target, scan_type)
        await send(1, "Port Scanner", "done", scan_results["portscan"])
        if await check_cancel(): return

        await send(1, "Subdomain Finder", "running")
        scan_results["subdomain"] = await asyncio.get_event_loop().run_in_executor(None, run_subdomain, target, scan_type)
        await send(1, "Subdomain Finder", "done", scan_results["subdomain"])
        if await check_cancel(): return

        await send(1, "Whois Lookup", "running")
        scan_results["whois"] = await asyncio.get_event_loop().run_in_executor(None, run_whois, target)
        await send(1, "Whois Lookup", "done", scan_results["whois"])
        if await check_cancel(): return

        await send(1, "DNS Lookup", "running")
        scan_results["dns"] = await asyncio.get_event_loop().run_in_executor(None, run_dns, target)
        await send(1, "DNS Lookup", "done", scan_results["dns"])
        if await check_cancel(): return

        await send(1, "Header Scanner", "running")
        scan_results["headers"] = await asyncio.get_event_loop().run_in_executor(None, run_headers, target, scan_type)
        await send(1, "Header Scanner", "done", scan_results["headers"])
        if await check_cancel(): return

        await send(1, "WAF Detector", "running")
        scan_results["waf"] = await asyncio.get_event_loop().run_in_executor(None, run_waf, target)
        await send(1, "WAF Detector", "done", scan_results["waf"])
        if await check_cancel(): return

        await send(1, "SSL Scanner", "running")
        scan_results["ssl"] = await asyncio.get_event_loop().run_in_executor(None, run_ssl, target, scan_type)
        await send(1, "SSL Scanner", "done", scan_results["ssl"])
        if await check_cancel(): return

        # ── RUN IN ALL SCANS (ALL TOOLS) ──────────────────────────────
        await send(1, "Robots.txt Analyzer", "running")
        scan_results["robots"] = await asyncio.get_event_loop().run_in_executor(None, robots_analyzer, target)
        await send(1, "Robots.txt Analyzer", "done", scan_results["robots"])
        if await check_cancel(): return

        await send(1, "Cookie Security", "running")
        scan_results["cookie"] = await asyncio.get_event_loop().run_in_executor(None, cookie_security_checker, target)
        await send(1, "Cookie Security", "done", scan_results["cookie"])
        if await check_cancel(): return

        await send(1, "Clickjacking Tester", "running")
        scan_results["clickjacking"] = await asyncio.get_event_loop().run_in_executor(None, clickjacking_tester, target)
        await send(1, "Clickjacking Tester", "done", scan_results["clickjacking"])
        if await check_cancel(): return

        await send(1, "DNS Brute Force", "running")
        scan_results["dns_brute"] = await asyncio.get_event_loop().run_in_executor(None, dns_brute_force, target)
        await send(1, "DNS Brute Force", "done", scan_results["dns_brute"])
        if await check_cancel(): return

        await send(1, "API Scanner", "running")
        scan_results["api_scan"] = await api_scanner(target)
        await send(1, "API Scanner", "done", scan_results["api_scan"])
        if await check_cancel(): return

        await send(1, "Reverse IP Lookup", "running")
        scan_results["reverse_ip"] = await asyncio.get_event_loop().run_in_executor(None, reverse_ip_lookup, target)
        await send(1, "Reverse IP Lookup", "done", scan_results["reverse_ip"])
        if await check_cancel(): return

        await send(1, "Technology Detector", "running")
        scan_results["tech_detect"] = await asyncio.get_event_loop().run_in_executor(None, tech_detector, target)
        await send(1, "Technology Detector", "done", scan_results["tech_detect"])
        if await check_cancel(): return
        # ──────────────────────────────────────────────────────────────

        if scan_type in ["medium", "deep"]:
            await send(1, "CVE Scanner", "running")
            scan_results["nuclei"] = await asyncio.get_event_loop().run_in_executor(None, run_nuclei, target, scan_type)
            await send(1, "CVE Scanner", "done", scan_results["nuclei"])
            if await check_cancel(): return

            await send(1, "URL Fuzzer", "running")
            scan_results["gobuster"] = await asyncio.get_event_loop().run_in_executor(None, run_gobuster, target, scan_type)
            await send(1, "URL Fuzzer", "done", scan_results["gobuster"])
            if await check_cancel(): return

            # ── RUN ONLY IN MEDIUM/DEEP SCANS ──
            await send(1, "Drupal Scanner", "running")
            scan_results["drupal"] = await asyncio.get_event_loop().run_in_executor(None, drupal_scanner, target)
            await send(1, "Drupal Scanner", "done", scan_results["drupal"])
            if await check_cancel(): return

            await send(1, "Joomla Scanner", "running")
            scan_results["joomla"] = await asyncio.get_event_loop().run_in_executor(None, joomla_scanner, target)
            await send(1, "Joomla Scanner", "done", scan_results["joomla"])
            if await check_cancel(): return

            await send(1, "Virtual Host Finder", "running")
            scan_results["vhost"] = await asyncio.get_event_loop().run_in_executor(None, vhost_fuzzer, target)
            await send(1, "Virtual Host Finder", "done", scan_results["vhost"])
            if await check_cancel(): return

            await send(1, "Shodan Lookup", "running")
            scan_results["shodan_scan"] = await asyncio.get_event_loop().run_in_executor(None, shodan_lookup, target)
            await send(1, "Shodan Lookup", "done", scan_results["shodan_scan"])
            if await check_cancel(): return

            await send(1, "Email Harvester", "running")
            scan_results["email_harvester"] = await asyncio.get_event_loop().run_in_executor(None, email_harvester, target)
            await send(1, "Email Harvester", "done", scan_results["email_harvester"])
            if await check_cancel(): return

            await send(1, "Subdomain Takeover", "running")
            scan_results["subdomain_takeover"] = await asyncio.get_event_loop().run_in_executor(None, subdomain_takeover, target)
            await send(1, "Subdomain Takeover", "done", scan_results["subdomain_takeover"])
            if await check_cancel(): return
            # ───────────────────────────────────

        if scan_type == "deep":
            await send(1, "Nikto Scanner", "running")
            scan_results["nikto"] = await asyncio.get_event_loop().run_in_executor(None, run_nikto, target)
            await send(1, "Nikto Scanner", "done", scan_results["nikto"])
            if await check_cancel(): return

            await send(1, "WordPress Scanner", "running")
            scan_results["wpscan"] = await asyncio.get_event_loop().run_in_executor(None, run_wpscan, target)
            await send(1, "WordPress Scanner", "done", scan_results["wpscan"])
            if await check_cancel(): return

        await send(2, "Cloudflare AI", "running")
        ai_analysis = await asyncio.get_event_loop().run_in_executor(None, analyze_with_ai, target, scan_results, scan_type)
        await send(2, "Cloudflare AI", "done", ai_analysis)
        if await check_cancel(): return

        attack_results = []
        if scan_type in ["medium", "deep"]:
            await send(3, "AI Attack Engine", "running")
            attack_results = await asyncio.get_event_loop().run_in_executor(
                None, execute_ai_attacks, target, ai_analysis.get("attack_recommendations", []), scan_type)
            await send(3, "AI Attack Engine", "done", {"attacks": attack_results})
            if await check_cancel(): return
        else:
            await send(3, "AI Attack Engine", "skipped", {"message": "Not included in light scan"})

        await send(4, "Report Generator", "running")
        report_path = await asyncio.get_event_loop().run_in_executor(
            None, generate_report, target, scan_results, ai_analysis, attack_results, scan_type)

        # Update active scan with scan_id
        scan_id = str(uuid.uuid4())
        if target in active_scans:
            active_scans[target]["scan_id"] = scan_id
            active_scans[target]["status"] = "complete"

        await scans_collection.insert_one({
            "_id": scan_id,
            "user_id": user_id,
            "target": target,
            "scan_type": scan_type,
            "scan_results": scan_results,
            "ai_analysis": ai_analysis,
            "attack_results": attack_results,
            "report_path": report_path,
            "created_at": datetime.now().isoformat(),
            "risk_level": ai_analysis.get("risk_level", "UNKNOWN"),
            "security_score": ai_analysis.get("security_score", 0),
        })

        await send(4, "Report Generator", "done", {
            "report_path": report_path,
            "scan_id": scan_id,
            "download_url": f"/api/fullscan/download/{target.replace('.', '_')}"
        })

        print(f"DEBUG: Attempting email for user_id={user_id}, target={target}")
        # ── Send scan complete email notification ──────────────────────────
        try:
            from utils.database import users_collection
            from utils.email import send_scan_complete_email
            from bson import ObjectId
            # Try ObjectId first, fall back to string
            try:
                user = await users_collection.find_one({"_id": ObjectId(user_id)})
            except:
                user = await users_collection.find_one({"_id": user_id})
            # Fall back to email lookup from JWT
            if not user:
                user = await users_collection.find_one({"email": user_email}) if user_email != "anonymous" else None
            if user and user.get("email"):
                send_scan_complete_email(
                    to_email=user["email"],
                    user_name=user.get("name", "User"),
                    target=target,
                    scan_id=scan_id,
                    risk_level=ai_analysis.get("risk_level", "UNKNOWN"),
                    security_score=ai_analysis.get("security_score", 0),
                    scan_type=scan_type,
                    critical_findings=len(ai_analysis.get("critical_findings", [])),
                )
                print(f"📧 Scan complete email sent to {user['email']}")
        except Exception as email_err:
            print(f"Email notification failed: {email_err}")

        await send(4, "VulnForge", "complete", {
            "scan_results": scan_results,
            "ai_analysis": ai_analysis,
            "attack_results": attack_results,
            "scan_id": scan_id,
            "scan_type": scan_type,
            "download_url": f"/api/fullscan/download/{target.replace('.', '_')}"
        })

    except WebSocketDisconnect:
        pass
    except Exception as e:
        await send(0, "VulnForge", "error", {"message": str(e)})
    finally:
        if target in active_scans:
            if active_scans[target].get("status") == "running":
                active_scans[target]["status"] = "error"
            if "event" in active_scans[target]:
                active_scans[target]["event"].set()
            websockets = list(active_scans[target].get("websockets", []))
            for ws in websockets:
                try:
                    await ws.close()
                except Exception:
                    pass


@router.get("/download/{filename}")
def download_report(filename: str):
    path = f"/tmp/vulnforge_report_{filename}.pdf"
    if os.path.exists(path):
        return FileResponse(path, filename=f"vulnforge_report_{filename}.pdf", media_type="application/pdf")
    return {"status": "error", "message": "Report not found"}

