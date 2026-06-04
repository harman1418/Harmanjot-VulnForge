from fastapi import APIRouter
import whois
import subprocess
import re
import httpx
import json

router = APIRouter()

def clean_val(val):
    if val is None:
        return "Not Available"
    if isinstance(val, list):
        # Join list items and remove duplicates
        items = sorted(list(set([str(v) for v in val if v])))
        return ", ".join(items) if items else "Not Available"
    return str(val)

def get_rdap_data(domain):
    """Fetch domain data using RDAP as a high-reliability fallback."""
    try:
        # Using rdap.org as a redirector/proxy
        url = f"https://rdap.org/domain/{domain}"
        with httpx.Client(follow_redirects=True, timeout=10.0) as client:
            response = client.get(url)
            if response.status_code == 200:
                data = response.json()
                
                # Extracting dates
                creation = "Not Available"
                expiry = "Not Available"
                for event in data.get("events", []):
                    if event.get("eventAction") == "registration":
                        creation = event.get("eventDate", creation)
                    elif event.get("eventAction") == "expiration":
                        expiry = event.get("eventDate", expiry)
                
                # Extracting nameservers
                ns = [n.get("ldhName") for n in data.get("nameservers", []) if n.get("ldhName")]
                
                # Extracting registrar
                registrar = "Not Available"
                for entity in data.get("entities", []):
                    if "registrar" in entity.get("roles", []):
                        # Look for vcard info
                        vcard = entity.get("vcardArray", [])
                        if len(vcard) > 1:
                            for entry in vcard[1]:
                                if entry[0] == "fn":
                                    registrar = entry[3]
                                    break
                
                return {
                    "domain_name": data.get("ldhName", domain),
                    "registrar": registrar,
                    "creation_date": creation,
                    "expiration_date": expiry,
                    "updated_date": "Not Available",
                    "name_servers": ", ".join(ns) if ns else "Not Available",
                    "status": ", ".join(data.get("status", [])) or "Active",
                    "emails": "Privacy Protected",
                    "org": "Privacy Protected",
                    "country": "Not Available"
                }
    except Exception:
        pass
    return None

@router.get("/")
def whois_lookup(target: str):
    try:
        # Clean target (remove http/https)
        domain = target.replace("https://", "").replace("http://", "").split("/")[0]

        # 1. Try with the whois library first
        try:
            w = whois.whois(domain)
            if w.domain_name:
                return {
                    "target": domain,
                    "status": "success",
                    "source": "library",
                    "data": {
                        "domain_name": clean_val(w.domain_name),
                        "registrar": clean_val(w.registrar),
                        "creation_date": clean_val(w.creation_date),
                        "expiration_date": clean_val(w.expiration_date),
                        "updated_date": clean_val(w.updated_date),
                        "name_servers": clean_val(w.name_servers),
                        "status": clean_val(w.status),
                        "emails": clean_val(w.emails),
                        "org": clean_val(w.org),
                        "country": clean_val(w.country),
                    }
                }
        except:
            pass
        
        # 2. Try RDAP fallback (Highly reliable for .app, .io, etc.)
        rdap = get_rdap_data(domain)
        if rdap:
            return {
                "target": domain,
                "status": "success",
                "source": "rdap",
                "data": rdap
            }

        # 3. Last resort: system whois command
        try:
            cmd = ["whois", domain]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            output = result.stdout
            
            if output:
                def extract(regex):
                    match = re.search(regex, output, re.IGNORECASE)
                    return match.group(1).strip() if match else "Not Available"

                return {
                    "target": domain,
                    "status": "success",
                    "source": "system_cmd",
                    "data": {
                        "domain_name": extract(r"Domain Name:\s*(.+)"),
                        "registrar": extract(r"Registrar:\s*(.+)"),
                        "creation_date": extract(r"Creation Date:\s*(.+)"),
                        "expiration_date": extract(r"Registry Expiry Date:\s*(.+)"),
                        "updated_date": extract(r"Updated Date:\s*(.+)"),
                        "name_servers": ", ".join(re.findall(r"Name Server:\s*(.+)", output, re.IGNORECASE)) or "Not Available",
                        "status": extract(r"Domain Status:\s*(.+)"),
                        "emails": extract(r"Registrant Email:\s*(.+)"),
                        "org": extract(r"Registrant Organization:\s*(.+)"),
                        "country": extract(r"Registrant Country:\s*(.+)"),
                    }
                }
        except:
            pass

        return {"status": "error", "message": "All Whois lookups failed. Target might be blocking requests."}

    except Exception as e:
        return {"status": "error", "message": str(e)}
