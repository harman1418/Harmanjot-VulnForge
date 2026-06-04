from fastapi import APIRouter
router = APIRouter()

DORK_TEMPLATES = [
    'site:{target} filetype:pdf',
    'site:{target} filetype:sql',
    'site:{target} inurl:admin',
    'site:{target} inurl:login',
    'site:{target} inurl:config',
    'site:{target} inurl:backup',
    'site:{target} inurl:dashboard',
    'site:{target} intitle:"index of"',
    'site:{target} "password" filetype:txt',
    'site:{target} inurl:.env',
    'site:{target} inurl:wp-admin',
    'site:{target} inurl:phpmyadmin',
]

@router.get("/")
def google_dork(target: str):
    try:
        clean = target.replace("https://","").replace("http://","").split("/")[0]
        dorks = [t.replace("{target}", clean) for t in DORK_TEMPLATES]
        return {
            "status": "success",
            "target": clean,
            "dorks": dorks,
            "google_links": [{"dork": d, "url": f"https://www.google.com/search?q={d.replace(' ', '+')}"}
                for d in dorks],
            "total": len(dorks),
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}
