"""
Authorization Server (AS) cho luồng MCP OAuth 2.1.

Vai trò: đăng nhập người dùng, cấp authorization code, đổi code lấy access_token.
Đây là bên "auth.example.com" mà user được điều hướng tới khi bấm Connect.

Nâng cấp so với file gốc (Resource Owner Password flow):
  - Password flow bị OAuth 2.1 loại bỏ vì phải nhập mật khẩu trực tiếp vào client
    (không phù hợp khi client là AI agent). Thay bằng Authorization Code + PKCE.
  - Thêm endpoint /authorize (trang login) - đây là "page OAuth" mà user thấy.
  - Thêm PKCE bắt buộc (code_challenge / code_verifier, method S256).
  - Thêm Dynamic Client Registration (RFC 7591) để MCP client tự đăng ký.
  - Thêm Authorization Server Metadata (RFC 8414) để MCP client tự khám phá endpoint.
  - Access token giờ có "aud" (audience) = resource server cụ thể (RFC 8707 Resource Indicators)
    để token không thể bị dùng lại ở MCP server khác.

Chạy demo:
    pip install fastapi uvicorn pyjwt "pwdlib[argon2]"
    uvicorn auth_server:app --port 8000 --reload

Tài khoản demo: username=johndoe / password=secret
"""

import base64
import hashlib
import os
import secrets
import time
from datetime import datetime, timedelta, timezone
from typing import Annotated
from urllib.parse import urlencode

import jwt
from fastapi import FastAPI, Form, HTTPException, Query, Request, status
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from jwt.exceptions import InvalidTokenError
from pwdlib import PasswordHash
from pydantic import BaseModel

# ----------------------------------------------------------------------------
# Cấu hình - đọc từ biến môi trường (Render tự set các biến này khi deploy).
# Local dev không set thì fallback về localhost để chạy `uv run uvicorn ...`.
# ----------------------------------------------------------------------------
ISSUER = os.environ.get("ISSUER_URL", "http://localhost:8000")
SECRET_KEY = os.environ["JWT_SECRET_KEY"] if "JWT_SECRET_KEY" in os.environ else "dev-only-insecure-secret-change-me"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 15
AUTH_CODE_EXPIRE_SECONDS = 60
REFRESH_TOKEN_EXPIRE_DAYS = 30

password_hash = PasswordHash.recommended()
DUMMY_HASH = password_hash.hash("dummypassword")

app = FastAPI(title="Demo MCP Authorization Server")

# ----------------------------------------------------------------------------
# "Database" giả lập (demo only - production dùng DB thật)
# ----------------------------------------------------------------------------
fake_users_db = {
    "johndoe": {
        "username": "johndoe",
        "full_name": "John Doe",
        "email": "johndoe@example.com",
        # bcrypt/argon2 hash của "secret"
        "hashed_password": "$argon2id$v=19$m=65536,t=3,p=4$wagCPXjifgvUFBzq4hqe3w$CYaIb8sB+wtD+Vu/P4uod1+Qof8h+1g7bbDlBID48Rc",
        "disabled": False,
    }
}

# client_id -> {redirect_uris, client_name, ...}   (từ Dynamic Client Registration)
registered_clients: dict[str, dict] = {}

# authorization_code -> {username, client_id, redirect_uri, scope, resource,
#                         code_challenge, code_challenge_method, expires_at}
auth_codes: dict[str, dict] = {}

# refresh_token -> {username, client_id, scope, resource, expires_at}
refresh_tokens: dict[str, dict] = {}


# ----------------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------------
def verify_password(plain_password: str, hashed_password: str) -> bool:
    return password_hash.verify(plain_password, hashed_password)


def authenticate_user(username: str, password: str):
    user = fake_users_db.get(username)
    if not user:
        # vẫn verify với dummy hash để tránh timing attack lộ user có tồn tại hay không
        verify_password(password, DUMMY_HASH)
        return None
    if not verify_password(password, user["hashed_password"]):
        return None
    return user


def create_access_token(*, username: str, client_id: str, scope: str, resource: str) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "iss": ISSUER,
        "sub": username,
        "aud": resource,          # RFC 8707: token chỉ dùng được cho resource server này
        "client_id": client_id,
        "scope": scope,
        "iat": now,
        "exp": now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def verify_pkce(code_verifier: str, code_challenge: str, method: str) -> bool:
    if method != "S256":
        return False
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    computed = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return secrets.compare_digest(computed, code_challenge)


# ----------------------------------------------------------------------------
# RFC 8414 - Authorization Server Metadata
# MCP client gọi endpoint này đầu tiên để "biết đường" tới /authorize, /token
# ----------------------------------------------------------------------------
@app.get("/.well-known/oauth-authorization-server")
async def authorization_server_metadata():
    return {
        "issuer": ISSUER,
        "authorization_endpoint": f"{ISSUER}/authorize",
        "token_endpoint": f"{ISSUER}/token",
        "registration_endpoint": f"{ISSUER}/register",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none"],  # public client, dùng PKCE thay secret
        "scopes_supported": ["weather:read"],
    }


# ----------------------------------------------------------------------------
# RFC 7591 - Dynamic Client Registration
# MCP client tự đăng ký (ngầm, user không thấy) lần đầu kết nối tới AS này
# ----------------------------------------------------------------------------
class RegisterRequest(BaseModel):
    redirect_uris: list[str]
    client_name: str | None = None
    token_endpoint_auth_method: str = "none"


@app.post("/register", status_code=201)
async def register_client(req: RegisterRequest):
    client_id = f"mcp-client-{secrets.token_urlsafe(12)}"
    registered_clients[client_id] = {
        "redirect_uris": req.redirect_uris,
        "client_name": req.client_name or "MCP Client",
        "token_endpoint_auth_method": req.token_endpoint_auth_method,
    }
    return {
        "client_id": client_id,
        "redirect_uris": req.redirect_uris,
        "client_name": req.client_name,
        "token_endpoint_auth_method": "none",
    }


# ----------------------------------------------------------------------------
# /authorize - đây chính là "trang OAuth" mà user được điều hướng tới khi Connect
# GET  -> hiển thị form login
# POST -> xác thực, tạo authorization code, redirect về client kèm ?code=...
# ----------------------------------------------------------------------------
@app.get("/authorize", response_class=HTMLResponse)
async def authorize_page(
    response_type: str = Query(...),
    client_id: str = Query(...),
    redirect_uri: str = Query(...),
    scope: str = Query("weather:read"),
    state: str = Query(...),
    code_challenge: str = Query(...),
    code_challenge_method: str = Query("S256"),
    resource: str = Query(...),  # RFC 8707: MCP server URL client muốn truy cập
):
    if response_type != "code":
        raise HTTPException(400, "unsupported_response_type")
    client = registered_clients.get(client_id)
    if not client or redirect_uri not in client["redirect_uris"]:
        raise HTTPException(400, "invalid_client_or_redirect_uri")

    hidden_fields = urlencode(
        {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "scope": scope,
            "state": state,
            "code_challenge": code_challenge,
            "code_challenge_method": code_challenge_method,
            "resource": resource,
        }
    )
    return f"""
    <html>
      <body style="font-family: sans-serif; max-width: 360px; margin: 80px auto;">
        <h2>{client['client_name']} muốn kết nối</h2>
        <p>Ứng dụng yêu cầu quyền: <b>{scope}</b> trên <code>{resource}</code></p>
        <form method="post" action="/authorize">
          <input type="hidden" name="auth_params" value="{hidden_fields}" />
          <input name="username" placeholder="Username" style="display:block;margin:8px 0;width:100%" />
          <input name="password" type="password" placeholder="Password" style="display:block;margin:8px 0;width:100%" />
          <button type="submit">Login & Allow</button>
        </form>
      </body>
    </html>
    """


@app.post("/authorize")
async def authorize_submit(
    username: Annotated[str, Form()],
    password: Annotated[str, Form()],
    auth_params: Annotated[str, Form()],
):
    from urllib.parse import parse_qsl

    params = dict(parse_qsl(auth_params))
    user = authenticate_user(username, password)
    if not user:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Sai username hoặc password")

    code = secrets.token_urlsafe(32)
    auth_codes[code] = {
        "username": username,
        "client_id": params["client_id"],
        "redirect_uri": params["redirect_uri"],
        "scope": params["scope"],
        "resource": params["resource"],
        "code_challenge": params["code_challenge"],
        "code_challenge_method": params["code_challenge_method"],
        "expires_at": time.time() + AUTH_CODE_EXPIRE_SECONDS,
    }

    redirect_qs = urlencode({"code": code, "state": params["state"]})
    return RedirectResponse(f"{params['redirect_uri']}?{redirect_qs}", status_code=302)


# ----------------------------------------------------------------------------
# /token - đổi authorization code (+ code_verifier) lấy access_token
# ----------------------------------------------------------------------------
class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "Bearer"
    expires_in: int
    refresh_token: str | None = None
    scope: str


@app.post("/token", response_model=TokenResponse)
async def token_endpoint(
    grant_type: Annotated[str, Form()],
    code: Annotated[str | None, Form()] = None,
    redirect_uri: Annotated[str | None, Form()] = None,
    client_id: Annotated[str | None, Form()] = None,
    code_verifier: Annotated[str | None, Form()] = None,
    refresh_token: Annotated[str | None, Form()] = None,
):
    if grant_type == "authorization_code":
        entry = auth_codes.pop(code, None) if code else None
        if not entry or entry["expires_at"] < time.time():
            raise HTTPException(400, "invalid_grant")
        if entry["client_id"] != client_id or entry["redirect_uri"] != redirect_uri:
            raise HTTPException(400, "invalid_grant")
        if not code_verifier or not verify_pkce(
            code_verifier, entry["code_challenge"], entry["code_challenge_method"]
        ):
            raise HTTPException(400, "invalid_grant: PKCE verification failed")

        access_token = create_access_token(
            username=entry["username"],
            client_id=entry["client_id"],
            scope=entry["scope"],
            resource=entry["resource"],
        )
        new_refresh = secrets.token_urlsafe(32)
        refresh_tokens[new_refresh] = {
            "username": entry["username"],
            "client_id": entry["client_id"],
            "scope": entry["scope"],
            "resource": entry["resource"],
            "expires_at": time.time() + REFRESH_TOKEN_EXPIRE_DAYS * 86400,
        }
        return TokenResponse(
            access_token=access_token,
            expires_in=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            refresh_token=new_refresh,
            scope=entry["scope"],
        )

    elif grant_type == "refresh_token":
        entry = refresh_tokens.get(refresh_token) if refresh_token else None
        if not entry or entry["expires_at"] < time.time():
            raise HTTPException(400, "invalid_grant")
        access_token = create_access_token(
            username=entry["username"],
            client_id=entry["client_id"],
            scope=entry["scope"],
            resource=entry["resource"],
        )
        return TokenResponse(
            access_token=access_token,
            expires_in=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            refresh_token=refresh_token,
            scope=entry["scope"],
        )

    raise HTTPException(400, "unsupported_grant_type")