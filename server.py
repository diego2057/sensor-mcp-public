"""
Estacion Meteorologica IoT - MCP Server
BIU SP26_CSE6011 - Diego Munoz Rodriguez

OAuth 2.0 con registro dinamico + cliente estatico pre-configurado
para conexion desde Claude.ai web y Claude Desktop.
"""
import os
import time
import secrets
from urllib.parse import urlencode

from fastmcp import FastMCP
from fastmcp.server.auth.auth import (
    OAuthProvider,
    AuthorizationCode,
    RefreshToken,
    AccessToken,
    ClientRegistrationOptions,
)
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken
from mcp.server.auth.provider import AuthorizationParams
from supabase import create_client

# ── Configuracion ────────────────────────────────────────────────────────────
SUPABASE_URL = os.environ["SUPABASE_URL"]
SUPABASE_KEY = os.environ["SUPABASE_KEY"]
SERVER_URL   = os.environ.get("SERVER_URL", "https://sensor-mcp-iot.onrender.com")

# client_id estatico para agregar en Claude.ai → Configuracion del conector
CLIENT_ID = os.environ.get("OAUTH_CLIENT_ID", "sensor-iot-biu-sp26-2026")

supabase = create_client(SUPABASE_URL, SUPABASE_KEY)


# ── OAuth Provider con almacenamiento en memoria ──────────────────────────────
class MemoryOAuthProvider(OAuthProvider):
    """
    Implementacion completa de OAuth 2.0 Authorization Server.
    - Registro dinamico habilitado (Claude.ai lo usa al primer intento)
    - Cliente estatico pre-registrado con CLIENT_ID conocido (fallback manual)
    - Tokens de larga duracion (30 dias) para minimizar re-autenticaciones
    """

    def __init__(self):
        super().__init__(
            base_url=SERVER_URL,
            client_registration_options=ClientRegistrationOptions(
                enabled=True,
                valid_scopes=["mcp"],
                default_scopes=["mcp"],
            ),
        )
        self._clients: dict[str, OAuthClientInformationFull] = {}
        self._codes:   dict[str, AuthorizationCode]          = {}
        self._tokens:  dict[str, AccessToken]                = {}
        self._refresh: dict[str, RefreshToken]               = {}

        # Pre-registrar cliente estatico (para cuando el usuario agrega el
        # client_id manualmente en la configuracion del conector de Claude.ai)
        self._clients[CLIENT_ID] = OAuthClientInformationFull(
            client_id=CLIENT_ID,
            redirect_uris=[
                "https://claude.ai/api/mcp/auth_callback",
                "https://claude.ai/oauth/callback",
                "https://claude.ai/api/mcp/oauth/callback",
                "https://claude.ai/",
            ],
            grant_types=["authorization_code"],
            response_types=["code"],
            token_endpoint_auth_method="none",   # cliente publico con PKCE
            client_name="Claude.ai - Estacion IoT",
            scope="mcp",
        )

    # ── Gestion de clientes ─────────────────────────────────────────────────
    async def get_client(
        self, client_id: str
    ) -> OAuthClientInformationFull | None:
        return self._clients.get(client_id)

    async def register_client(
        self, client_info: OAuthClientInformationFull
    ) -> None:
        self._clients[client_info.client_id] = client_info

    # ── Flujo de autorizacion ───────────────────────────────────────────────
    async def authorize(
        self, client: OAuthClientInformationFull, params: AuthorizationParams
    ) -> str:
        """
        Auto-aprueba la solicitud y genera el codigo de autorizacion.
        Redirige de vuelta al cliente con ?code=...&state=...
        """
        code = secrets.token_urlsafe(32)
        self._codes[code] = AuthorizationCode(
            code=code,
            scopes=params.scopes or ["mcp"],
            expires_at=time.time() + 300,           # 5 minutos
            client_id=client.client_id,
            code_challenge=params.code_challenge,
            redirect_uri=params.redirect_uri,
            redirect_uri_provided_explicitly=params.redirect_uri_provided_explicitly,
            resource=params.resource,
            subject="sensor-iot-user",
        )

        redirect = (
            str(params.redirect_uri)
            if params.redirect_uri
            else str(client.redirect_uris[0])
        )
        query: dict[str, str] = {"code": code}
        if params.state:
            query["state"] = params.state
        return f"{redirect}?{urlencode(query)}"

    async def load_authorization_code(
        self,
        client: OAuthClientInformationFull,
        authorization_code: str,
    ) -> AuthorizationCode | None:
        entry = self._codes.get(authorization_code)
        if entry and entry.expires_at > time.time():
            return entry
        return None

    async def exchange_authorization_code(
        self,
        client: OAuthClientInformationFull,
        authorization_code: AuthorizationCode,
    ) -> OAuthToken:
        """Emite access_token y refresh_token de larga duracion (30 dias)."""
        ttl = 60 * 60 * 24 * 30   # 30 dias en segundos
        exp = time.time() + ttl

        at_str = secrets.token_urlsafe(32)
        rt_str = secrets.token_urlsafe(32)

        self._tokens[at_str] = AccessToken(
            token=at_str,
            client_id=client.client_id,
            scopes=authorization_code.scopes,
            expires_at=exp,
            resource=authorization_code.resource,
            subject=authorization_code.subject,
        )
        self._refresh[rt_str] = RefreshToken(
            token=rt_str,
            client_id=client.client_id,
            scopes=authorization_code.scopes,
            expires_at=exp,
            subject=authorization_code.subject,
        )
        # Invalidar el codigo ya usado
        self._codes.pop(authorization_code.code, None)

        return OAuthToken(
            access_token=at_str,
            token_type="bearer",
            expires_in=ttl,
            scope=" ".join(authorization_code.scopes),
            refresh_token=rt_str,
        )

    # ── Gestion de tokens ───────────────────────────────────────────────────
    async def load_access_token(self, token: str) -> AccessToken | None:
        at = self._tokens.get(token)
        if at and at.expires_at > time.time():
            return at
        return None

    async def load_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: str,
    ) -> RefreshToken | None:
        rt = self._refresh.get(refresh_token)
        if rt and rt.expires_at > time.time():
            return rt
        return None

    async def exchange_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: RefreshToken,
        scopes: list[str],
    ) -> OAuthToken:
        ttl = 60 * 60 * 24 * 30
        exp = time.time() + ttl
        new_at = secrets.token_urlsafe(32)

        self._tokens[new_at] = AccessToken(
            token=new_at,
            client_id=client.client_id,
            scopes=scopes or refresh_token.scopes,
            expires_at=exp,
            subject=refresh_token.subject,
        )
        return OAuthToken(
            access_token=new_at,
            token_type="bearer",
            expires_in=ttl,
            scope=" ".join(scopes or refresh_token.scopes),
            refresh_token=refresh_token.token,   # rotar si se desea
        )

    async def revoke_token(
        self, token: AccessToken | RefreshToken
    ) -> None:
        self._tokens.pop(getattr(token, "token", None), None)
        self._refresh.pop(getattr(token, "token", None), None)


# ── Instancia FastMCP ────────────────────────────────────────────────────────
oauth = MemoryOAuthProvider()
mcp   = FastMCP("Estacion Meteorologica IoT - Diego Munoz", auth=oauth)


# ── Herramientas MCP ─────────────────────────────────────────────────────────
@mcp.tool()
def get_latest_reading() -> dict:
    """Retorna la ultima lectura del sensor SHTC3 (temperatura y humedad)."""
    result = (
        supabase.table("sensor_readings")
        .select("*")
        .order("recorded_at", desc=True)
        .limit(1)
        .execute()
    )
    if result.data:
        return result.data[0]
    return {"error": "No hay lecturas disponibles"}


@mcp.tool()
def get_historical_data(limit: int = 10) -> list:
    """Retorna el historico de lecturas del sensor SHTC3. limit: numero de registros (max 50)."""
    result = (
        supabase.table("sensor_readings")
        .select("*")
        .order("recorded_at", desc=True)
        .limit(min(limit, 50))
        .execute()
    )
    return result.data


@mcp.tool()
def get_sensor_stats() -> dict:
    """Retorna estadisticas (min, max, promedio) de temperatura y humedad."""
    result = (
        supabase.table("sensor_readings")
        .select("temperature, humidity, recorded_at")
        .order("recorded_at", desc=True)
        .limit(50)
        .execute()
    )
    if not result.data:
        return {"error": "Sin datos"}

    temps = [r["temperature"] for r in result.data if r.get("temperature") is not None]
    hums  = [r["humidity"]    for r in result.data if r.get("humidity")    is not None]

    return {
        "temperatura": {
            "min":      round(min(temps), 2),
            "max":      round(max(temps), 2),
            "promedio": round(sum(temps) / len(temps), 2),
        },
        "humedad": {
            "min":      round(min(hums), 2),
            "max":      round(max(hums), 2),
            "promedio": round(sum(hums) / len(hums), 2),
        },
        "total_lecturas": len(result.data),
    }


if __name__ == "__main__":
    port = int(os.getenv("PORT", 8000))
    mcp.run(transport="sse", host="0.0.0.0", port=port)
