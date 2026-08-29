"""The OIDC token endpoint — server-to-server only (SP -> IdP), never called by a
browser. Mounted on the *internal* app (see ``idp/main.py``) so it can be kept off any
publicly published port: a stolen SP `private_key_jwt` key is only useful to whoever can
reach this listener, and network placement is one real lever against that.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Form
from fastapi.responses import JSONResponse
from starlette import status

from fabric.common.audit import Event, Severity
from fabric.common.oauth import CLIENT_ASSERTION_TYPE, GRANT_AUTHORIZATION_CODE
from fabric.idp.api.endpoints import TOKEN_PATH
from fabric.idp.deps import AuditDep, SessionDep, SettingsDep
from fabric.idp.service.errors import InvalidClientError, InvalidRequestError, ServiceError
from fabric.idp.service.flows import OIDCFlowService

router = APIRouter(tags=["token"])


def _error_status(err: ServiceError) -> int:
    if isinstance(err, InvalidClientError):
        return status.HTTP_401_UNAUTHORIZED
    return status.HTTP_400_BAD_REQUEST


@router.post(TOKEN_PATH)
async def token(
    session: SessionDep,
    settings: SettingsDep,
    audit: AuditDep,
    grant_type: Annotated[str, Form()],
    code: Annotated[str, Form()],
    redirect_uri: Annotated[str, Form()],
    client_id: Annotated[str, Form()],
    code_verifier: Annotated[str, Form()],
    client_assertion: Annotated[str, Form()],
    client_assertion_type: Annotated[str, Form()] = CLIENT_ASSERTION_TYPE,
) -> JSONResponse:
    try:
        if grant_type != GRANT_AUTHORIZATION_CODE:
            raise InvalidRequestError(f"unsupported grant_type: {grant_type}")
        flow = OIDCFlowService(session, settings)
        result = await flow.exchange_code(
            client_id=client_id,
            code=code,
            code_verifier=code_verifier,
            redirect_uri=redirect_uri,
            client_assertion_type=client_assertion_type,
            client_assertion=client_assertion,
            token_endpoint=f"{settings.idp_internal_base_url}{TOKEN_PATH}",
            audit=audit,
        )
    except ServiceError as exc:
        await audit.record(
            Event.TOKEN_DENIED,
            Severity.WARNING,
            client_id=client_id,
            outcome="denied",
            detail={"error": exc.error, "error_description": exc.description},
        )
        return JSONResponse(
            status_code=_error_status(exc),
            content={"error": exc.error, "error_description": exc.description},
        )
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content=result.model_dump(),
        headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
    )
