"""
MCP Server (Resource Server) - phiên bản sửa từ file gốc của bạn.

Thay đổi so với bản gốc:
  1. httpx2 -> httpx (bản gốc bị lỗi chính tả, package không tồn tại).
  2. transport "stdio" -> "streamable-http": OAuth chỉ áp dụng cho MCP server
     chạy qua HTTP/mạng. stdio là subprocess local, không có khái niệm
     Authorization header nên không cần (và không thể) auth theo OAuth.
  3. Thêm TokenVerifier + AuthSettings: biến server này thành OAuth 2.1
     Resource Server đúng chuẩn MCP spec - nó CHỈ verify token, không tự
     issue token (việc issue token là của auth_server.py).
  4. Khi có auth=..., SDK tự động:
       - Publish /.well-known/oauth-protected-resource/mcp (RFC 9728)
       - Trả 401 kèm header WWW-Authenticate trỏ tới metadata ở trên
         khi request không có / có token không hợp lệ.
     -> Đây chính là bước "Client thử connect -> 401 -> tự tìm authorization
        server" trong luồng đã thảo luận, mình không cần tự viết tay.

Chạy demo:
    pip install "mcp[cli]" httpx pyjwt
    python weather_mcp_server.py
    # server sẽ nghe tại http://127.0.0.1:8001/mcp
"""

import os
from typing import Any

import httpx
import jwt
from jwt.exceptions import InvalidTokenError
from pydantic import AnyHttpUrl

from mcp.server import MCPServer
from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.provider import AccessToken, TokenVerifier
from mcp.server.auth.settings import AuthSettings

# ----------------------------------------------------------------------------
# Cấu hình - đọc từ biến môi trường (Render set các biến này khi deploy).
# AUTH_SERVER_URL phải trỏ đúng domain thật của auth_server.py sau khi deploy.
# RESOURCE_SERVER_URL phải trỏ đúng domain thật của chính server này + "/mcp".
# JWT_SECRET_KEY phải GIỐNG HỆT secret của auth_server.py (demo dùng HS256
# chia sẻ secret; production nên dùng JWKS/RS256 để RS không cần biết secret).
# ----------------------------------------------------------------------------
AUTH_SERVER_URL = os.environ.get("AUTH_SERVER_URL", "http://localhost:8000")
RESOURCE_SERVER_URL = os.environ.get("RESOURCE_SERVER_URL", "http://127.0.0.1:8001/mcp")
SECRET_KEY = os.environ["JWT_SECRET_KEY"] if "JWT_SECRET_KEY" in os.environ else "dev-only-insecure-secret-change-me"
ALGORITHM = "HS256"
REQUIRED_SCOPES = ["weather:read"]

# Render cấp PORT động qua biến môi trường PORT, và yêu cầu bind 0.0.0.0
HOST = "0.0.0.0" if "PORT" in os.environ else "127.0.0.1"
PORT = int(os.environ.get("PORT", 8001))


class JWTTokenVerifier(TokenVerifier):
    """
    Verify access token do auth_server.py cấp.

    Demo dùng HS256 (shared secret) để khớp với auth_server.py cho đơn giản.
    Production nên dùng RS256/ES256 + JWKS endpoint của AS (không share secret
    giữa AS và RS), hoặc dùng token introspection (RFC 7662) nếu AS không phát
    JWT tự-chứa (self-contained).
    """

    async def verify_token(self, token: str) -> AccessToken | None:
        try:
            payload = jwt.decode(
                token,
                SECRET_KEY,
                algorithms=[ALGORITHM],
                audience=RESOURCE_SERVER_URL,  # đảm bảo token được cấp CHO server này (RFC 8707)
                issuer=AUTH_SERVER_URL,
            )
        except InvalidTokenError:
            return None

        scopes = payload.get("scope", "").split()
        return AccessToken(
            token=token,
            client_id=payload.get("client_id", "unknown"),
            scopes=scopes,
            expires_at=int(payload["exp"]),
        )


mcp = MCPServer(
    "weather",
    host=HOST,
    port=PORT,
    token_verifier=JWTTokenVerifier(),
    auth=AuthSettings(
        issuer_url=AnyHttpUrl(AUTH_SERVER_URL),
        resource_server_url=AnyHttpUrl(RESOURCE_SERVER_URL),
        required_scopes=REQUIRED_SCOPES,
    ),
)

NWS_API_BASE = "https://api.weather.gov"
USER_AGENT = "weather-app/1.0"


async def make_nws_request(url: str) -> dict[str, Any] | None:
    """Gọi NWS API kèm xử lý lỗi."""
    headers = {"User-Agent": USER_AGENT, "Accept": "application/geo+json"}
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(url, headers=headers, timeout=30.0)
            response.raise_for_status()
            return response.json()
        except Exception:
            return None


def format_alert(feature: dict) -> str:
    props = feature["properties"]
    return f"""
Event: {props.get("event", "Unknown")}
Area: {props.get("areaDesc", "Unknown")}
Severity: {props.get("severity", "Unknown")}
Description: {props.get("description", "No description available")}
Instructions: {props.get("instruction", "No specific instructions provided")}
"""


@mcp.tool()
async def get_alerts(state: str) -> str:
    """Get weather alerts for a US state.

    Args:
        state: Two-letter US state code (e.g. CA, NY)
    """
    # Ví dụ dùng danh tính người gọi lấy từ token, nếu cần audit/log/rate-limit theo user:
    caller = get_access_token()
    if caller:
        print(f"[audit] get_alerts called by client_id={caller.client_id}, scopes={caller.scopes}")

    url = f"{NWS_API_BASE}/alerts/active/area/{state}"
    data = await make_nws_request(url)

    if not data or "features" not in data:
        return "Unable to fetch alerts or no alerts found."
    if not data["features"]:
        return "No active alerts for this state."

    alerts = [format_alert(feature) for feature in data["features"]]
    return "\n---\n".join(alerts)


@mcp.tool()
async def get_forecast(latitude: float, longitude: float) -> str:
    """Get weather forecast for a location.

    Args:
        latitude: Latitude of the location
        longitude: Longitude of the location
    """
    points_url = f"{NWS_API_BASE}/points/{latitude},{longitude}"
    points_data = await make_nws_request(points_url)
    if not points_data:
        return "Unable to fetch forecast data for this location."

    forecast_url = points_data["properties"]["forecast"]
    forecast_data = await make_nws_request(forecast_url)
    if not forecast_data:
        return "Unable to fetch detailed forecast."

    periods = forecast_data["properties"]["periods"]
    forecasts = []
    for period in periods[:5]:
        forecast = f"""
{period["name"]}:
Temperature: {period["temperature"]}°{period["temperatureUnit"]}
Wind: {period["windSpeed"]} {period["windDirection"]}
Forecast: {period["detailedForecast"]}
"""
        forecasts.append(forecast)

    return "\n---\n".join(forecasts)


if __name__ == "__main__":
    # QUAN TRỌNG: OAuth chỉ hoạt động trên transport HTTP, không phải stdio
    mcp.run(transport="streamable-http")