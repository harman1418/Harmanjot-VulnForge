from fastapi import APIRouter
from Wappalyzer import Wappalyzer, WebPage
import warnings
import subprocess
import json

router = APIRouter()

@router.get("/")
def tech_detector(target: str):
    try:
        warnings.filterwarnings("ignore")
        
        url = f"https://{target}" if not target.startswith("http") else target
        
        # Use curl to fetch the page - it handles modern TLS and Vercel better than Python libraries
        cmd = [
            "curl", "-s", "-L", "-k",
            "-A", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
            "-H", "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
            "-H", "Accept-Language: en-US,en;q=0.9",
            "--compressed",
            "-i", # include headers in output
            url
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
        
        if not result.stdout:
            # Fallback to HTTP if HTTPS failed (curl might exit with error)
            if url.startswith("https://"):
                url = url.replace("https://", "http://", 1)
                cmd[-1] = url
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
        
        output = result.stdout
        
        # Split headers and body
        parts = output.split("\r\n\r\n", 1)
        if len(parts) < 2:
            # Try single newline for non-compliant servers
            parts = output.split("\n\n", 1)
            
        if len(parts) >= 2:
            header_text = parts[0]
            body = parts[1]
        else:
            header_text = ""
            body = output

        # Parse headers for Wappalyzer
        headers = {}
        for line in header_text.splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip()] = v.strip()
        
        # Create WebPage and analyze
        webpage = WebPage(url, body, headers)
        wappalyzer = Wappalyzer.latest()
        techs = wappalyzer.analyze_with_categories(webpage)
        
        # Convert to frontend format
        technologies = {}
        for tech_name, data in techs.items():
            for category in data.get("categories", ["Miscellaneous"]):
                if category not in technologies:
                    technologies[category] = []
                technologies[category].append(tech_name)
                
        return {
            "target": target,
            "status": "success",
            "total_categories": len(technologies),
            "technologies": technologies
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}
