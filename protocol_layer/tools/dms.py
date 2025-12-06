import asyncio
import base64
import logging
import os
from typing import Any

import httpx
from dotenv import load_dotenv
from fastmcp import FastMCP
from pydantic import BaseModel, ConfigDict, Field

load_dotenv()
log = logging.getLogger(__name__)

# config
DMS_URL = os.getenv("DMS_API_BASE_URL", "").rstrip("/")
KC_URL = os.getenv("KEYCLOAK_URL", "").rstrip("/")
KC_REALM = os.getenv("KEYCLOAK_REALM", "master")
AUTH_MODE = os.getenv("DMS_AUTH_MODE", "keycloak" if KC_URL else "dms").lower()
VERIFY_TLS = os.getenv("DMS_TLS_VERIFY", "true").lower() not in {"0", "false", "no"}

BASE_URL = DMS_URL or "http://127.0.0.1:9000"

# persistent session - stores cookies / auth headers after login
_session = httpx.AsyncClient(
    base_url=BASE_URL,
    timeout=httpx.Timeout(20.0, connect=5.0),
    verify=VERIFY_TLS,
    follow_redirects=True,
    http2=True,
    limits=httpx.Limits(max_connections=20, max_keepalive_connections=10),
    headers={"Content-Type": "application/json"},
)


def _missing_config() -> dict[str, Any]:
    return {"status": "error", "message": "DMS_API_BASE_URL is not configured"}


def _error_from_response(op: str, err: httpx.HTTPStatusError) -> dict[str, Any]:
    return {
        "status": "error",
        "operation": op,
        "status_code": err.response.status_code,
        "message": err.response.text,
    }


def _dms_ready() -> bool:
    if not DMS_URL:
        log.warning(
            "DMS_API_BASE_URL not provided; DMS tools unavailable until configured."
        )
        return False
    return True


async def _call_dms(
    endpoint: str, payload: Any, *, expect_binary: bool = False
) -> dict[str, Any]:
    if not _dms_ready():
        return _missing_config()

    attempts = 3
    backoff = 0.3

    for attempt in range(1, attempts + 1):
        try:
            resp = await _session.post(endpoint, json=payload)
            resp.raise_for_status()
            if expect_binary:
                return {
                    "status": "success",
                    "mime_type": resp.headers.get(
                        "Content-Type", "application/octet-stream"
                    ),
                    "data": base64.b64encode(resp.content).decode(),
                }
            return resp.json()
        except httpx.HTTPStatusError as exc:
            # Do not retry client errors.
            if exc.response is not None and exc.response.status_code < 500:
                return _error_from_response(endpoint, exc)
            log.warning(
                "DMS HTTP error (attempt %d/%d): %s",
                attempt,
                attempts,
                exc.response.text,
            )
            last_exc = exc
        except httpx.RequestError as exc:
            log.warning("DMS network error (attempt %d/%d): %s", attempt, attempts, exc)
            last_exc = exc
        except Exception as exc:  # pragma: no cover - defensive
            log.exception("dms call failed (attempt %d/%d)", attempt, attempts)
            last_exc = exc

        if attempt < attempts:
            await asyncio.sleep(backoff)
            backoff *= 2
        else:
            msg = getattr(last_exc, "response", None)
            text = msg.text if hasattr(msg, "text") else str(last_exc)
            return {"status": "error", "operation": endpoint, "message": text}


class DMSModel(BaseModel):
    """base model that renders camelCase payloads and strips None values."""

    model_config = ConfigDict(
        populate_by_name=True, extra="forbid", str_strip_whitespace=True
    )

    def envelope(self) -> list[dict[str, Any]]:
        """DMS APIs expect a JSON array containing a single object."""
        return [self.model_dump(by_alias=True, exclude_none=True)]


class ServiceAccountLogin(BaseModel):
    client_id: str | None = Field(
        default=os.getenv("DMS_CLIENT_ID"), description="Keycloak client id"
    )
    client_secret: str | None = Field(
        default=os.getenv("DMS_CLIENT_SECRET"), description="Keycloak client secret"
    )
    username: str | None = Field(
        default=os.getenv("DMS_USERNAME"),
        description="Fallback username for legacy /login",
    )
    password: str | None = Field(
        default=os.getenv("DMS_PASSWORD"),
        description="Fallback password for legacy /login",
    )


class ClientScopedRequest(DMSModel):
    client_id: str = Field(..., alias="clientId", description="Client UUID")
    user_login_id: str = Field(..., alias="userLoginId", description="User login id")


class ClientInfoRequest(ClientScopedRequest):
    """Request body for /clients"""


class UserProfileRequest(ClientScopedRequest):
    timezone: str = Field(
        ..., alias="timezone", description="IANA timezone, e.g. 'America/New_York'"
    )


class DocumentSearch(DMSModel):
    client_id: str = Field(
        ..., alias="clientId", description="Client UUID to scope the search"
    )
    user_login_id: str = Field(
        ..., alias="userLoginId", description="User login id to scope the search"
    )
    search_text: str = Field(
        ..., alias="searchText", description="Full text query passed to Solr"
    )
    filters: dict[str, Any] | None = Field(
        None, alias="filters", description="Optional advanced filters map"
    )


class DocumentIdentifier(ClientScopedRequest):
    document_id: str = Field(..., alias="documentId", description="Document UUID")


class UploadDocumentRequest(ClientScopedRequest):
    folder_name: str = Field(..., alias="folderName")
    base64_content: str = Field(
        ..., alias="base64_content", description="base64 encoded file content"
    )
    file_name: str = Field(..., alias="fileName")
    file_extension: str = Field(..., alias="fileExtension")
    label: str | None = Field(None, alias="label")
    tags: str | None = Field(None, alias="tags")
    document_type: str | None = Field(None, alias="documentType")
    subscription_id: str | None = Field(None, alias="subscriptionId")
    folder_metadata: dict[str, Any] | None = Field(None, alias="folder_metadata")


class CreateUserRequest(ClientScopedRequest):
    username: str = Field(..., alias="username")
    email: str = Field(..., alias="email")
    firstname: str = Field(..., alias="firstname")
    lastname: str = Field(..., alias="lastname")
    phoneno: str | None = Field(None, alias="phoneno")
    address: str | None = Field(None, alias="address")
    is_create_default_folders: bool = Field(True, alias="iscreatedefaultfolders")


class SearchUsersRequest(ClientScopedRequest):
    search_text: str = Field(
        ..., alias="searchText", description="Search string (Solr powered)"
    )


class ShareDocumentRequest(ClientScopedRequest):
    recipient_user_login_ids: list[str] = Field(
        ...,
        alias="recipeintUserLoginId",
        description="List of user login ids to share with",
    )
    edit_flag: bool = Field(False, alias="editFlag")
    admin_flag: bool = Field(False, alias="adminFlag")
    document_id: str | None = Field(None, alias="documentId")
    folder_id: str | None = Field(None, alias="folderId")


class RenameDocumentRequest(DocumentIdentifier):
    new_name: str = Field(..., alias="newName")


class MoveFileRequest(DocumentIdentifier):
    folder_id: str = Field(..., alias="folderId")


class DeleteFolderOrFileRequest(ClientScopedRequest):
    folder_id: str | None = Field(None, alias="folderId")
    document_id: str | None = Field(None, alias="documentId")
    is_folder: bool = Field(False, alias="isFolder")


class StreamImageRequest(DocumentIdentifier):
    """Streaming image shares same payload as download but separate endpoint."""


def register_dms_tools(mcp: FastMCP) -> None:
    """register dms tools to mcp server."""

    async def _login_via_keycloak(creds: ServiceAccountLogin) -> dict[str, Any]:
        client_id = creds.client_id or os.getenv("DMS_CLIENT_ID")
        client_secret = creds.client_secret or os.getenv("DMS_CLIENT_SECRET")
        if not (client_id and client_secret):
            return {
                "status": "error",
                "message": "Missing client credentials for Keycloak auth",
            }

        url = f"{KC_URL}/realms/{KC_REALM}/protocol/openid-connect/token"
        data = {
            "client_id": client_id,
            "client_secret": client_secret,
            "grant_type": "client_credentials",
        }

        try:
            async with httpx.AsyncClient(timeout=10.0, verify=VERIFY_TLS) as client:
                resp = await client.post(
                    url,
                    data=data,
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                )
                resp.raise_for_status()
                token_payload = resp.json()
        except httpx.HTTPStatusError as exc:
            log.error("keycloak auth failed: %s", exc.response.text)
            return _error_from_response("keycloak_login", exc)
        except Exception as exc:  # pragma: no cover - defensive
            log.exception("keycloak auth unexpected failure")
            return {"status": "error", "message": str(exc)}

        token = token_payload.get("access_token")
        if not token:
            return {
                "status": "error",
                "message": "Keycloak response missing access_token",
            }

        _session.headers["Authorization"] = f"Bearer {token}"
        return {
            "status": "success",
            "token_type": token_payload.get("token_type"),
            "expires_in": token_payload.get("expires_in"),
        }

    async def _login_via_dms(creds: ServiceAccountLogin) -> dict[str, Any]:
        username = creds.username or os.getenv("DMS_USERNAME")
        password = creds.password or os.getenv("DMS_PASSWORD")
        if not (username and password):
            return {
                "status": "error",
                "message": "Missing DMS_USERNAME / DMS_PASSWORD for /login auth",
            }

        payload = {"username": username, "password": password}
        return await _call_dms("/login", payload)

    @mcp.tool()
    async def login_service_account(creds: ServiceAccountLogin) -> dict[str, Any]:
        """Authenticate with DMS/Keycloak. Stores the token in the shared httpx session."""
        if AUTH_MODE == "dms" or not KC_URL:
            return await _login_via_dms(creds)
        return await _login_via_keycloak(creds)

    @mcp.tool()
    async def search_documents(params: DocumentSearch) -> dict[str, Any]:
        """Search documents in the DMS corpus. Requires a prior login."""
        if "Authorization" not in _session.headers and AUTH_MODE != "dms":
            return {
                "status": "error",
                "message": "Not authenticated. Call login_service_account first.",
            }

        return await _call_dms("/documents/search", params.envelope())

    @mcp.tool()
    async def get_client_information(body: ClientInfoRequest) -> dict[str, Any]:
        """Wraps POST /clients."""
        return await _call_dms("/clients", body.envelope())

    @mcp.tool()
    async def get_user_profile(body: UserProfileRequest) -> dict[str, Any]:
        """Wraps POST /consumers to fetch folders/documents tree."""
        return await _call_dms("/consumers", body.envelope())

    @mcp.tool()
    async def create_user(body: CreateUserRequest) -> dict[str, Any]:
        """Create a DMS user via POST /createuser."""
        return await _call_dms("/createuser", body.envelope())

    @mcp.tool()
    async def search_users(body: SearchUsersRequest) -> dict[str, Any]:
        """Search for users via POST /searchuser."""
        return await _call_dms("/searchuser", body.envelope())

    @mcp.tool()
    async def get_document(body: DocumentIdentifier) -> dict[str, Any]:
        """Retrieve a document metadata/payload descriptor via POST /documents."""
        return await _call_dms("/documents", body.envelope())

    @mcp.tool()
    async def upload_document(body: UploadDocumentRequest) -> dict[str, Any]:
        """Upload a document via POST /uploaddocuments (async Kafka flow)."""
        return await _call_dms("/uploaddocuments", body.envelope())

    @mcp.tool()
    async def download_document(body: DocumentIdentifier) -> dict[str, Any]:
        """Download a single document via POST /downloadDocument (base64 encoded result)."""
        result = await _call_dms(
            "/downloadDocument", body.envelope(), expect_binary=True
        )
        return result

    @mcp.tool()
    async def stream_image(body: StreamImageRequest) -> dict[str, Any]:
        """Stream an image as base64 via POST /streamimage."""
        return await _call_dms("/streamimage", body.envelope(), expect_binary=True)

    @mcp.tool()
    async def share_document(body: ShareDocumentRequest) -> dict[str, Any]:
        """Share a document/folder via POST /sharedocument."""
        return await _call_dms("/sharedocument", body.envelope())

    @mcp.tool()
    async def rename_document(body: RenameDocumentRequest) -> dict[str, Any]:
        """Rename a document via POST /renameDocument."""
        return await _call_dms("/renameDocument", body.envelope())

    @mcp.tool()
    async def move_file(body: MoveFileRequest) -> dict[str, Any]:
        """Move a document between folders via POST /moveFile."""
        return await _call_dms("/moveFile", body.envelope())

    @mcp.tool()
    async def delete_folder_or_file(body: DeleteFolderOrFileRequest) -> dict[str, Any]:
        """Delete a folder/file (moves to trash) via POST /deleteFolderOrFile."""
        return await _call_dms("/deleteFolderOrFile", body.envelope())
