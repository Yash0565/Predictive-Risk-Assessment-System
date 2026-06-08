"""Enterprise service layer: multi-tenant authorization, RBAC, and an audited
risk-assessment service.

The security-critical logic (authentication, tenant isolation, RBAC decisions,
audit logging) lives here as framework-agnostic, fully-tested Python. An HTTP
framework (Flask/FastAPI) is only ever a thin transport adapter over this core,
so the authorization model can be reasoned about and tested in isolation.
"""
