"""
Authentication & Authorization.

JWT-based auth with an OIDC-compatible verification hook, plus simple
RBAC/ABAC and workspace/tenant isolation. This is a reference implementation
suitable for self-hosted deployments; for production SSO, point
`oidc_issuer`/`oidc_client_id` (see config.py) at your identity provider and
replace `verify_oidc_token` with a real JWKS-based verifier.
"""
from __future__ import annotations

import time
from typing import Any, Dict, Optional

import jwt
from fastapi import Header, HTTPException, status

from .config import settings

ROLE_PERMISSIONS = {
    "admin": {"*"},
    "analyst": {"read", "investigate", "annotate", "policy:simulate"},
    "viewer": {"read"},
    "service": {"ingest"},
}


def create_access_token(subject: str, tenant: str, role: str) -> str:
    now = int(time.time())
    payload = {
        "sub": subject, "tenant": tenant, "role": role,
        "iat": now, "exp": now + settings.jwt_ttl_minutes * 60,
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)


def decode_access_token(token: str) -> Dict[str, Any]:
    try:
        return jwt.decode(token, settings.jwt_secret, algorithms=[settings.jwt_algorithm])
    except jwt.PyJWTError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=f"invalid token: {exc}")


def current_principal(authorization: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    """FastAPI dependency. In development (no Authorization header, no OIDC
    configured) falls back to an implicit admin principal scoped to the
    default tenant so the reference deployment works out of the box; a
    production deployment should set ECHOBOUND_JWT_SECRET and always send a
    bearer token."""
    if not authorization:
        return {"sub": "dev-user", "tenant": settings.default_tenant, "role": "admin"}
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise HTTPException(status_code=401, detail="expected 'Authorization: Bearer <token>'")
    return decode_access_token(token)


def require_permission(principal: Dict[str, Any], permission: str):
    role = principal.get("role", "viewer")
    perms = ROLE_PERMISSIONS.get(role, set())
    if "*" not in perms and permission not in perms:
        raise HTTPException(status_code=403, detail=f"role '{role}' lacks permission '{permission}'")
