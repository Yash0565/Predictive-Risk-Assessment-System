"""Deny-by-default RBAC policy engine (OPA/Cedar-style decisions).

Roles map to permission sets; a request is authorized only if the principal's
role explicitly grants the requested action. Anything not granted is denied.
The policy is data (a dict), so it can be externalized to a policy file or a
policy service (OPA/Cedar) without changing call sites.
"""

from __future__ import annotations

from dataclasses import dataclass

# action strings: "<resource>:<verb>"
ROLE_PERMISSIONS: dict[str, set[str]] = {
    "owner": {
        "assessment:create", "assessment:read", "assessment:list", "assessment:delete",
        "audit:read", "policy:read", "policy:write", "member:manage",
    },
    "admin": {
        "assessment:create", "assessment:read", "assessment:list", "assessment:delete",
        "audit:read", "policy:read",
    },
    "analyst": {
        "assessment:create", "assessment:read", "assessment:list",
    },
    "viewer": {
        "assessment:read", "assessment:list",
    },
}


@dataclass(frozen=True)
class Principal:
    actor: str
    tenant: str
    role: str


class AuthenticationError(Exception):
    """Raised when an API key cannot be resolved to a principal."""


class AuthorizationError(Exception):
    """Raised when an authenticated principal lacks permission."""


def permissions_for(role: str) -> set[str]:
    return set(ROLE_PERMISSIONS.get(role, set()))


def is_allowed(principal: Principal, action: str, resource_tenant: str | None = None) -> bool:
    """Deny-by-default: the role must grant the action AND the resource (if any)
    must belong to the principal's tenant (hard tenant isolation)."""
    if resource_tenant is not None and resource_tenant != principal.tenant:
        return False
    return action in permissions_for(principal.role)


def require(principal: Principal, action: str, resource_tenant: str | None = None) -> None:
    if not is_allowed(principal, action, resource_tenant):
        raise AuthorizationError(
            f"{principal.actor} (role={principal.role}, tenant={principal.tenant}) "
            f"is not permitted to perform {action!r}"
            + (f" on tenant {resource_tenant!r}" if resource_tenant else "")
        )
