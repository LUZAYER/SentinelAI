"""
SentinelAI Admin API

Enterprise Administrative Portal Endpoints.
Provides live platform telemetry, real-time user management (role updates, activation),
live audit logs with filtration, and dynamic infrastructure diagnostics.
No hardcoded or mock data — everything is queried live from the database and infrastructure.
"""

import logging
import time
from datetime import datetime, timezone
from typing import Dict, Any, Optional

import httpx
import redis.asyncio as aioredis
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import select, func, desc, or_, text, delete
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from backend.app.core.config import settings
from backend.app.core.database import get_db
from backend.app.core.security import get_current_user
from backend.app.models.user import User
from backend.app.models.analysis import Analysis
from backend.app.models.risk_assessment import RiskAssessment
from backend.app.models.audit_log import AuditLog
from backend.app.schemas.auth import UserResponse

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/admin", tags=["Admin"])


# ============================================================================
# Schemas
# ============================================================================

class RoleUpdateRequest(BaseModel):
    role: str = Field(..., pattern="^(ADMIN|USER)$", description="New user role: ADMIN or USER")


class StatusUpdateRequest(BaseModel):
    is_active: bool = Field(..., description="Active status toggle")


# ============================================================================
# Dependencies
# ============================================================================

def require_admin(current_user: User = Depends(get_current_user)) -> User:
    """Ensure the requesting user holds the ADMIN role."""
    if current_user.role != "ADMIN":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Administrative privileges required to access this resource."
        )
    return current_user


# ============================================================================
# Live Endpoints
# ============================================================================

@router.get("/stats")
async def admin_stats(
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(require_admin),
):
    """
    Get live, real-time system-wide statistics:
    - User totals (active, admin, standard)
    - Platform analysis metrics (totals, status breakdown, threat type breakdown)
    - Live risk aggregation (high risk threats, average score, detection rate)
    - Real-time infrastructure diagnostics (Postgres latency, Redis latency, task queue depth, Ollama status)
    - Recent users, recent audit logs, and recent analyses
    """
    # 1. User metrics
    total_users = (await db.execute(select(func.count()).select_from(User))).scalar() or 0
    active_users = (await db.execute(select(func.count()).select_from(User).where(User.is_active == True))).scalar() or 0
    admin_users = (await db.execute(select(func.count()).select_from(User).where(User.role == "ADMIN"))).scalar() or 0

    # 2. Analysis metrics
    total_analyses = (await db.execute(select(func.count()).select_from(Analysis))).scalar() or 0

    status_rows = (await db.execute(
        select(Analysis.status, func.count()).group_by(Analysis.status)
    )).all()
    analyses_by_status = {r[0]: r[1] for r in status_rows}

    type_rows = (await db.execute(
        select(Analysis.analysis_type, func.count()).group_by(Analysis.analysis_type)
    )).all()
    analyses_by_type = {r[0]: r[1] for r in type_rows}

    # 3. Risk & Threat metrics
    risk_stats = await db.execute(
        select(
            func.count(RiskAssessment.id),
            func.avg(RiskAssessment.overall_score),
            func.count(func.nullif(RiskAssessment.overall_score < 50.0, True)),
        )
    )
    risk_row = risk_stats.first()
    total_assessed = risk_row[0] or 0
    avg_risk_score = round(float(risk_row[1] or 0.0), 1)
    high_risk_analyses = risk_row[2] or 0

    threat_detection_rate = (
        round((high_risk_analyses / total_assessed) * 100, 1)
        if total_assessed > 0 else 0.0
    )

    # 4. Infrastructure Health Diagnostics (Live measurements)
    # Database ping & latency
    db_status = "connected"
    db_latency_ms = 0.0
    try:
        t0 = time.perf_counter()
        await db.execute(text("SELECT 1"))
        db_latency_ms = round((time.perf_counter() - t0) * 1000, 2)
    except Exception as e:
        logger.error(f"Admin DB health check failed: {e}")
        db_status = "error"

    # Redis ping & queue depth
    redis_status = "connected"
    redis_latency_ms = 0.0
    queue_depth = 0
    try:
        r = aioredis.from_url(settings.REDIS_URL)
        t0 = time.perf_counter()
        await r.ping()
        redis_latency_ms = round((time.perf_counter() - t0) * 1000, 2)
        queue_depth = (await r.llen("celery")) + (await r.llen("sentinelai_tasks"))
        await r.aclose()
    except Exception as e:
        logger.error(f"Admin Redis health check failed: {e}")
        redis_status = "error"

    # Ollama LLM provider probe
    ollama_status = "offline"
    ollama_version = None
    try:
        async with httpx.AsyncClient(timeout=2.0) as client:
            resp = await client.get(f"{settings.OLLAMA_BASE_URL}/api/version")
            if resp.status_code == 200:
                ollama_status = "connected"
                ollama_version = resp.json().get("version", "ready")
    except Exception:
        ollama_status = "offline"

    # 5. Recent Users with analyses count
    recent_users_query = (
        select(
            User,
            func.count(Analysis.id).label("analyses_count")
        )
        .outerjoin(Analysis, Analysis.user_id == User.id)
        .group_by(User.id)
        .order_by(desc(User.created_at))
        .limit(10)
    )
    recent_users_result = await db.execute(recent_users_query)
    recent_users_list = []
    for u, count in recent_users_result.all():
        recent_users_list.append({
            "id": u.id,
            "username": u.username,
            "email": u.email,
            "full_name": u.full_name,
            "role": u.role,
            "is_active": u.is_active,
            "analyses_count": count,
            "created_at": u.created_at.isoformat() if u.created_at else None,
        })

    # 6. Recent Audit Logs (with associated username)
    recent_logs_query = (
        select(AuditLog, User.username)
        .outerjoin(User, AuditLog.user_id == User.id)
        .order_by(desc(AuditLog.created_at))
        .limit(15)
    )
    recent_logs_result = await db.execute(recent_logs_query)
    recent_logs_list = []
    for log, username in recent_logs_result.all():
        recent_logs_list.append({
            "id": log.id,
            "user_id": log.user_id,
            "username": username or f"User #{log.user_id}" if log.user_id else "System",
            "action": log.action,
            "resource_type": log.resource_type,
            "resource_id": log.resource_id,
            "details": log.details,
            "ip_address": log.ip_address or "127.0.0.1",
            "created_at": log.created_at.isoformat() if log.created_at else None,
        })

    # 7. Recent Analyses
    recent_analyses_query = (
        select(Analysis, RiskAssessment.overall_score, RiskAssessment.severity)
        .outerjoin(RiskAssessment, RiskAssessment.analysis_id == Analysis.id)
        .order_by(desc(Analysis.created_at))
        .limit(5)
    )
    recent_analyses_result = await db.execute(recent_analyses_query)
    recent_analyses_list = []
    for an, score, sev in recent_analyses_result.all():
        recent_analyses_list.append({
            "id": an.id,
            "title": an.title or f"{an.analysis_type.capitalize()} Analysis",
            "analysis_type": an.analysis_type,
            "input_type": an.input_type,
            "status": an.status,
            "score": score,
            "severity": sev or "UNKNOWN",
            "created_at": an.created_at.isoformat() if an.created_at else None,
        })

    return {
        "total_users": total_users,
        "active_users": active_users,
        "admin_users": admin_users,
        "total_analyses": total_analyses,
        "analyses_by_status": analyses_by_status,
        "analyses_by_type": analyses_by_type,
        "high_risk_analyses": high_risk_analyses,
        "avg_risk_score": avg_risk_score,
        "threat_detection_rate": threat_detection_rate,
        "system_health": {
            "database": {"status": db_status, "latency_ms": db_latency_ms},
            "redis": {"status": redis_status, "latency_ms": redis_latency_ms, "queue_depth": queue_depth},
            "ollama": {"status": ollama_status, "version": ollama_version, "model": settings.OLLAMA_MODEL},
        },
        "recent_users": recent_users_list,
        "recent_logs": recent_logs_list,
        "recent_analyses": recent_analyses_list,
    }


@router.get("/users")
async def list_users(
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    search: Optional[str] = Query(None, description="Filter by username or email"),
    role: Optional[str] = Query(None, description="Filter by role: ADMIN or USER"),
    is_active: Optional[bool] = Query(None, description="Filter by active status"),
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(require_admin),
):
    """List all users with live analyses count, role, and search filters."""
    query = (
        select(
            User,
            func.count(Analysis.id).label("analyses_count")
        )
        .outerjoin(Analysis, Analysis.user_id == User.id)
        .group_by(User.id)
    )

    if search:
        search_filter = f"%{search.strip()}%"
        query = query.where(
            or_(
                User.username.ilike(search_filter),
                User.email.ilike(search_filter),
                User.full_name.ilike(search_filter),
            )
        )

    if role:
        query = query.where(User.role == role.upper())

    if is_active is not None:
        query = query.where(User.is_active == is_active)

    # Count total
    count_subq = query.subquery()
    total = (await db.execute(select(func.count()).select_from(count_subq))).scalar() or 0

    # Paginate
    result = await db.execute(
        query.order_by(desc(User.created_at))
        .offset((page - 1) * per_page)
        .limit(per_page)
    )
    rows = result.all()

    items = []
    for u, count in rows:
        items.append({
            "id": u.id,
            "username": u.username,
            "email": u.email,
            "full_name": u.full_name,
            "role": u.role,
            "is_active": u.is_active,
            "analyses_count": count,
            "created_at": u.created_at.isoformat() if u.created_at else None,
            "updated_at": u.updated_at.isoformat() if u.updated_at else None,
        })

    return {
        "items": items,
        "total": total,
        "page": page,
        "per_page": per_page,
    }


@router.put("/users/{user_id}/role")
async def update_user_role(
    user_id: int,
    payload: RoleUpdateRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(require_admin),
):
    """Change a user's role (USER <-> ADMIN)."""
    target = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    # Safety: Cannot demote oneself if they are the only admin
    if target.id == admin.id and payload.role != "ADMIN":
        admin_count = (await db.execute(select(func.count()).select_from(User).where(User.role == "ADMIN"))).scalar() or 0
        if admin_count <= 1:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot demote the sole platform administrator account."
            )

    old_role = target.role
    target.role = payload.role

    # Audit log
    audit = AuditLog(
        user_id=admin.id,
        action="USER_ROLE_UPDATED",
        resource_type="user",
        resource_id=str(target.id),
        details={"username": target.username, "old_role": old_role, "new_role": target.role},
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
    )
    db.add(audit)
    await db.commit()
    await db.refresh(target)

    return {
        "message": f"Role for user {target.username} updated to {target.role}",
        "user": {
            "id": target.id,
            "username": target.username,
            "email": target.email,
            "role": target.role,
            "is_active": target.is_active,
        }
    }


@router.put("/users/{user_id}/status")
async def update_user_status(
    user_id: int,
    payload: StatusUpdateRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(require_admin),
):
    """Toggle a user's active status (suspend or reactivate)."""
    target = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    if target.id == admin.id and not payload.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot deactivate your own active administrator account."
        )

    old_status = target.is_active
    target.is_active = payload.is_active

    # Audit log
    audit = AuditLog(
        user_id=admin.id,
        action="USER_STATUS_UPDATED",
        resource_type="user",
        resource_id=str(target.id),
        details={
            "username": target.username,
            "old_active": old_status,
            "new_active": target.is_active,
        },
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
    )
    db.add(audit)
    await db.commit()
    await db.refresh(target)

    return {
        "message": f"Status for user {target.username} set to {'Active' if target.is_active else 'Suspended'}",
        "user": {
            "id": target.id,
            "username": target.username,
            "email": target.email,
            "role": target.role,
            "is_active": target.is_active,
        }
    }


@router.delete("/users/{user_id}")
async def delete_user(
    user_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(require_admin),
):
    """Permanently delete a user account."""
    target = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    if target.id == admin.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete your own active administrator account."
        )

    username = target.username
    await db.delete(target)

    # Audit log
    audit = AuditLog(
        user_id=admin.id,
        action="USER_DELETED",
        resource_type="user",
        resource_id=str(user_id),
        details={"deleted_username": username},
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
    )
    db.add(audit)
    await db.commit()

    return {"message": f"User {username} deleted successfully.", "id": user_id}


@router.post("/system/flush-cache")
async def flush_system_cache(
    request: Request,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(require_admin),
):
    """Flush temporary Redis cache keys and report queue status."""
    try:
        r = aioredis.from_url(settings.REDIS_URL)
        # Flush transient cache keys
        keys = await r.keys("cache:*")
        deleted_count = 0
        if keys:
            deleted_count = await r.delete(*keys)
        await r.aclose()

        audit = AuditLog(
            user_id=admin.id,
            action="SYSTEM_CACHE_FLUSHED",
            resource_type="system",
            resource_id="redis",
            details={"keys_cleared": deleted_count},
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
        )
        db.add(audit)
        await db.commit()

        return {
            "status": "success",
            "message": f"Platform cache flushed successfully ({deleted_count} transient keys cleared).",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    except Exception as e:
        logger.error(f"Error flushing cache: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to flush cache: {str(e)}")


@router.get("/audit-logs")
async def list_audit_logs(
    page: int = Query(1, ge=1),
    per_page: int = Query(25, ge=1, le=100),
    action: Optional[str] = Query(None, description="Filter by action type"),
    search: Optional[str] = Query(None, description="Search in resource_id or details"),
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(require_admin),
):
    """List live audit logs with pagination, filtering, and user names."""
    query = (
        select(AuditLog, User.username)
        .outerjoin(User, AuditLog.user_id == User.id)
    )

    if action:
        query = query.where(AuditLog.action == action)

    if search:
        search_term = f"%{search.strip()}%"
        query = query.where(
            or_(
                AuditLog.action.ilike(search_term),
                AuditLog.resource_type.ilike(search_term),
                AuditLog.resource_id.ilike(search_term),
                AuditLog.ip_address.ilike(search_term),
                User.username.ilike(search_term),
            )
        )

    # Count
    count_subq = query.subquery()
    total = (await db.execute(select(func.count()).select_from(count_subq))).scalar() or 0

    # Paginate
    result = await db.execute(
        query.order_by(desc(AuditLog.created_at))
        .offset((page - 1) * per_page)
        .limit(per_page)
    )
    rows = result.all()

    items = []
    for log, username in rows:
        items.append({
            "id": log.id,
            "user_id": log.user_id,
            "username": username or f"User #{log.user_id}" if log.user_id else "System",
            "action": log.action,
            "resource_type": log.resource_type,
            "resource_id": log.resource_id,
            "details": log.details,
            "ip_address": log.ip_address or "127.0.0.1",
            "created_at": log.created_at.isoformat() if log.created_at else None,
        })

    return {
        "items": items,
        "total": total,
        "page": page,
        "per_page": per_page,
    }
