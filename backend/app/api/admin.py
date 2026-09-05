"""
Admin API

Endpoints for admin users to view system statistics, users, and audit logs.
All endpoints require ADMIN role.
"""

import logging

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select, func, desc
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.core.database import get_db
from backend.app.core.security import get_current_admin
from backend.app.models.user import User
from backend.app.models.analysis import Analysis
from backend.app.models.audit_log import AuditLog
from backend.app.schemas.auth import UserResponse

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/admin", tags=["Admin"])


@router.get("/users")
async def list_users(
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(get_current_admin),
):
    """List all users (admin only)."""
    total = (await db.execute(select(func.count()).select_from(User))).scalar() or 0

    result = await db.execute(
        select(User)
        .order_by(desc(User.created_at))
        .offset((page - 1) * per_page)
        .limit(per_page)
    )
    users = result.scalars().all()

    return {
        "items": [UserResponse.model_validate(u) for u in users],
        "total": total,
        "page": page,
        "per_page": per_page,
    }


@router.get("/stats")
async def admin_stats(
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(get_current_admin),
):
    """Get system-wide statistics (admin only)."""
    total_users = (await db.execute(select(func.count()).select_from(User))).scalar() or 0
    total_analyses = (await db.execute(select(func.count()).select_from(Analysis))).scalar() or 0

    # By status
    status_rows = (await db.execute(
        select(Analysis.status, func.count()).group_by(Analysis.status)
    )).all()

    # By type
    type_rows = (await db.execute(
        select(Analysis.analysis_type, func.count()).group_by(Analysis.analysis_type)
    )).all()

    return {
        "total_users": total_users,
        "total_analyses": total_analyses,
        "analyses_by_status": {r[0]: r[1] for r in status_rows},
        "analyses_by_type": {r[0]: r[1] for r in type_rows},
    }


@router.get("/audit-logs")
async def list_audit_logs(
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
    action: str | None = Query(None),
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(get_current_admin),
):
    """List audit logs (admin only)."""
    query = select(AuditLog)
    if action:
        query = query.where(AuditLog.action == action)

    total = (await db.execute(
        select(func.count()).select_from(query.subquery())
    )).scalar() or 0

    result = await db.execute(
        query.order_by(desc(AuditLog.created_at))
        .offset((page - 1) * per_page)
        .limit(per_page)
    )
    logs = result.scalars().all()

    return {
        "items": [
            {
                "id": log.id,
                "user_id": log.user_id,
                "action": log.action,
                "resource_type": log.resource_type,
                "resource_id": log.resource_id,
                "details": log.details,
                "ip_address": log.ip_address,
                "created_at": log.created_at.isoformat() if log.created_at else None,
            }
            for log in logs
        ],
        "total": total,
        "page": page,
        "per_page": per_page,
    }
