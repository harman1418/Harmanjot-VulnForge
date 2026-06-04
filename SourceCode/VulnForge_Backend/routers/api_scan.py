from fastapi import APIRouter
import httpx
import asyncio

router = APIRouter()

@router.get("/")
async def api_scanner(target: str):
    try:
        url = f"https://{target}" if not target.startswith("http") else target
        endpoints = [
            "/api/v1", "/api/v2", "/api/v3", "/swagger.json", "/openapi.json", "/api-docs",
            "/v1/api-docs", "/v2/api-docs", "/v3/api-docs", "/swagger-ui.html", "/graphql", "/graphiql"
        ]
        
        found = []
        async with httpx.AsyncClient(verify=False, timeout=10) as client:
            tasks = [client.get(f"{url.rstrip('/')}{ep}") for ep in endpoints]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for ep, res in zip(endpoints, results):
                if not isinstance(res, Exception) and res.status_code in [200, 401, 403]:
                    found.append({"endpoint": ep, "status_code": res.status_code, "length": len(res.content)})
                    
        return {"target": target, "status": "success", "total": len(found), "endpoints": found}
    except Exception as e:
        return {"status": "error", "message": str(e)}
