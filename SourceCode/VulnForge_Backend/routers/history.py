from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import FileResponse
from utils.database import scans_collection
from typing import List
from pydantic import BaseModel
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


class BulkDeleteRequest(BaseModel):
    scan_ids: List[str]


@router.get("/")
async def get_all_scans(request: Request):
    user = get_current_user(request)
    user_id = user.get("user_id")
    try:
        cursor = scans_collection.find(
            {"user_id": user_id},
            {
                "_id": 1, "target": 1, "created_at": 1,
                "risk_level": 1, "security_score": 1,
                "scan_type": 1, "ai_analysis": 1,
            }
        ).sort("created_at", -1).limit(100)

        scans = []
        async for scan in cursor:
            scans.append({
                "id": str(scan["_id"]),
                "target": scan.get("target", ""),
                "created_at": scan.get("created_at", ""),
                "risk_level": scan.get("risk_level", "UNKNOWN"),
                "security_score": scan.get("security_score", 0),
                "scan_type": scan.get("scan_type", "medium"),
                "executive_summary": scan.get("ai_analysis", {}).get("executive_summary", ""),
                "critical_findings_count": len(scan.get("ai_analysis", {}).get("critical_findings", [])),
            })

        return {"status": "success", "scans": scans}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/clear/all")
async def clear_all_scans(request: Request):
    user = get_current_user(request)
    user_id = user.get("user_id")
    try:
        result = await scans_collection.delete_many({"user_id": user_id})
        return {"status": "success", "deleted": result.deleted_count}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/bulk/delete")
async def bulk_delete_scans(request: Request, body: BulkDeleteRequest):
    user = get_current_user(request)
    user_id = user.get("user_id")
    try:
        result = await scans_collection.delete_many({
            "_id": {"$in": body.scan_ids},
            "user_id": user_id
        })
        return {"status": "success", "deleted": result.deleted_count}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/download/{scan_id}")
async def download_scan_report(scan_id: str, request: Request):
    user = get_current_user(request)
    user_id = user.get("user_id")
    try:
        scan = await scans_collection.find_one({"_id": scan_id, "user_id": user_id})
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")

        target = scan.get("target", "unknown").replace(".", "_")
        path = f"/tmp/vulnforge_report_{target}.pdf"

        if os.path.exists(path):
            return FileResponse(path, filename=f"vulnforge_{target}.pdf", media_type="application/pdf")

        from routers.fullscan import generate_report
        new_path = generate_report(
            scan["target"],
            scan.get("scan_results", {}),
            scan.get("ai_analysis", {}),
            scan.get("attack_results", []),
            scan.get("scan_type", "medium")
        )
        return FileResponse(new_path, filename=f"vulnforge_{target}.pdf", media_type="application/pdf")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{scan_id}")
async def get_scan(scan_id: str, request: Request):
    user = get_current_user(request)
    user_id = user.get("user_id")
    try:
        scan = await scans_collection.find_one({"_id": scan_id, "user_id": user_id})
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        scan["id"] = str(scan["_id"])
        del scan["_id"]
        return {"status": "success", "scan": scan}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/{scan_id}")
async def delete_scan(scan_id: str, request: Request):
    user = get_current_user(request)
    user_id = user.get("user_id")
    try:
        result = await scans_collection.delete_one({"_id": scan_id, "user_id": user_id})
        if result.deleted_count == 0:
            raise HTTPException(status_code=404, detail="Scan not found")
        return {"status": "success", "message": "Scan deleted"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
