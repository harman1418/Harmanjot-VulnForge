from fastapi import APIRouter, HTTPException, Request
from utils.database import targets_collection, scans_collection
from pydantic import BaseModel
from datetime import datetime
from urllib.parse import urlparse
import jwt
import os

router = APIRouter()

JWT_SECRET = os.getenv("SECRET_KEY", "vulnforge_secret_2024")
JWT_ALGORITHM = "HS256"


def get_current_user(request: Request):
    auth = request.headers.get("authorization", "")
    # Fallback: check HttpOnly cookie
    if not auth:
        auth = request.cookies.get("access_token", "")
    if auth:
        auth = auth.strip().strip('"')
    if not auth.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Not authenticated")
    token = auth.split(" ")[1]
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except:
        raise HTTPException(status_code=401, detail="Invalid or expired token")


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


class TargetRequest(BaseModel):
    target: str


@router.get("/")
async def get_targets(request: Request):
    user = get_current_user(request)
    user_id = user.get("user_id")
    try:
        cursor = targets_collection.find(
            {"user_id": user_id},
            {"_id": 0}
        ).sort("created_at", -1)

        targets = []
        async for t in cursor:
            scan_count = await scans_collection.count_documents({
                "target": t["target"],
                "user_id": user_id
            })
            t["scan_count"] = scan_count
            targets.append(t)

        return {"status": "success", "targets": targets}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/")
async def add_target(request: Request, body: TargetRequest):
    user = get_current_user(request)
    user_id = user_id = user.get("user_id")
    try:
        target = clean_target_domain(body.target)

        existing = await targets_collection.find_one({
            "target": target,
            "user_id": user_id
        })
        if existing:
            raise HTTPException(status_code=400, detail="Target already exists")

        await targets_collection.insert_one({
            "target": target,
            "user_id": user_id,
            "created_at": datetime.now().isoformat(),
        })

        return {"status": "success", "message": f"Target {target} added"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/{target:path}")
async def delete_target(target: str, request: Request):
    user = get_current_user(request)
    user_id = user.get("user_id")
    try:
        target = clean_target_domain(target)
        result = await targets_collection.delete_one({
            "target": target,
            "user_id": user_id
        })
        if result.deleted_count == 0:
            raise HTTPException(status_code=404, detail="Target not found")
        return {"status": "success", "message": f"Target {target} deleted"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
