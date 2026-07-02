# app/database/context.py
from __future__ import annotations

import re
from contextvars import ContextVar, Token

# Represents the current tenant database context.
# Default is "master" (pointing to settings.DATABASE_PATH).
tenant_context: ContextVar[str] = ContextVar("tenant_context", default="master")

_SAFE_TENANT_ID = re.compile(r"^[A-Za-z0-9_-]+$")


def get_tenant_context() -> str:
    return tenant_context.get()


def set_tenant_context(tenant_id: str) -> Token[str]:
    tenant_id = (tenant_id or "master").strip() or "master"
    if tenant_id != "master" and not _SAFE_TENANT_ID.fullmatch(tenant_id):
        raise ValueError("Invalid tenant identifier")
    return tenant_context.set(tenant_id)


def reset_tenant_context(token: Token[str]) -> None:
    tenant_context.reset(token)
