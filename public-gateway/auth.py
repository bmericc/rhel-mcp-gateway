"""Cockpit hesabıyla kimlik doğrulama.

- Web paneli: kullanıcı adı/şifre Cockpit'e (COCKPIT_AUTH_URL) doğrulatılır.
- MCP istemcileri (/sse):
    * OAuth 2.1 (claude.ai, Claude Code vb.): istemci /authorize'a yönlendirir, kullanıcı
      Cockpit hesabıyla giriş yapar, istemci erişim token'ı alır.
    * HTTP Basic: Cockpit kullanıcı adı/şifresi doğrudan başlıkta.
    * MCP_API_KEY: sabit token (geriye dönük uyumluluk, opsiyonel).
"""
import base64
import hashlib
import json
import os
import secrets
import time
from typing import Any

from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    RefreshToken,
    TokenError,
    construct_redirect_uri,
)
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken

import cockpit_client
from i18n import t

ACCESS_TOKEN_TTL = 3600
REFRESH_TOKEN_TTL = 30 * 24 * 3600
AUTH_CODE_TTL = 300
LOGIN_REQUEST_TTL = 600
BASIC_CACHE_TTL = 300
SCOPE = "mcp"


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


class CockpitAuthenticator:
    """Kullanıcı adı/şifreyi Cockpit'e doğrulatır; izinli kullanıcı listesini uygular."""

    def __init__(self, url: str, verify_tls: bool = False, allowed_users: set[str] | None = None):
        self.url = url
        self.verify_tls = verify_tls
        self.allowed_users = allowed_users or set()
        self._basic_cache: dict[str, float] = {}

    def is_allowed(self, username: str) -> bool:
        return not self.allowed_users or username in self.allowed_users

    async def login(self, username: str, password: str) -> str | None:
        """Başarılıysa None, değilse kullanıcıya gösterilecek hata mesajını döner."""
        if not username or not password:
            return t("Username and password are required.")
        try:
            await cockpit_client.check_login(self.url, username, password, verify_tls=self.verify_tls)
        except cockpit_client.CockpitAuthError:
            return t("Wrong username or password.")
        except cockpit_client.CockpitError:
            return t("Could not reach Cockpit; the login could not be verified.")
        if not self.is_allowed(username):
            return t("This user is not allowed to access the gateway.")
        return None

    async def check_basic(self, header_value: str) -> str | None:
        """'Basic ...' başlığını doğrular; başarılıysa kullanıcı adını döner.

        Her MCP bağlantısında Cockpit'e gitmemek için başarılı girişler kısa süre önbelleklenir.
        """
        try:
            username, _, password = base64.b64decode(header_value[6:]).decode().partition(":")
        except Exception:
            return None
        key = _hash(f"{username}\0{password}")
        if self._basic_cache.get(key, 0) > time.time() and self.is_allowed(username):
            return username
        if await self.login(username, password) is None:
            self._basic_cache[key] = time.time() + BASIC_CACHE_TTL
            return username
        return None


class CockpitOAuthProvider:
    """MCP SDK'nın OAuthAuthorizationServerProvider arayüzü.

    Kayıtlı istemciler ve token'lar (hash'lenmiş olarak) bir JSON dosyasında saklanır,
    böylece gateway yeniden başlasa da kullanıcıların tekrar giriş yapması gerekmez.
    """

    def __init__(self, store_path: str, login_url: str, token_policy: str = ""):
        self.store_path = store_path
        self.login_url = login_url
        # Giriş token'ı (MCP_API_KEY) eklenir veya değiştirilirse eski oturumlar geçersiz olsun diye
        # token'ın hash'i saklanır; farklıysa kayıtlı erişim/refresh token'ları silinir.
        self.token_policy = _hash(token_policy) if token_policy else ""
        self.clients: dict[str, OAuthClientInformationFull] = {}
        self.access_tokens: dict[str, AccessToken] = {}
        self.refresh_tokens: dict[str, RefreshToken] = {}
        self.codes: dict[str, AuthorizationCode] = {}
        self.pending: dict[str, tuple[str, AuthorizationParams, float]] = {}
        self._load()

    # --- Kalıcılık ---

    def _load(self):
        if not os.path.exists(self.store_path):
            return
        try:
            with open(self.store_path) as f:
                data = json.load(f)
        except Exception:
            return
        self.clients = {k: OAuthClientInformationFull.model_validate(v) for k, v in data.get("clients", {}).items()}
        if data.get("token_policy", "") != self.token_policy:
            # Giriş kuralları değişti: herkes yeniden giriş yapmalı
            self._save()
            return
        self.access_tokens = {k: AccessToken.model_validate(v) for k, v in data.get("access_tokens", {}).items()}
        self.refresh_tokens = {k: RefreshToken.model_validate(v) for k, v in data.get("refresh_tokens", {}).items()}

    def _save(self):
        now = time.time()
        self.access_tokens = {k: v for k, v in self.access_tokens.items() if not v.expires_at or v.expires_at > now}
        self.refresh_tokens = {k: v for k, v in self.refresh_tokens.items() if not v.expires_at or v.expires_at > now}
        data = {
            "token_policy": self.token_policy,
            "clients": {k: v.model_dump(mode="json") for k, v in self.clients.items()},
            "access_tokens": {k: v.model_dump(mode="json") for k, v in self.access_tokens.items()},
            "refresh_tokens": {k: v.model_dump(mode="json") for k, v in self.refresh_tokens.items()},
        }
        os.makedirs(os.path.dirname(self.store_path) or ".", exist_ok=True)
        tmp = self.store_path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(data, f)
        os.chmod(tmp, 0o600)
        os.replace(tmp, self.store_path)

    # --- İstemci kaydı ---

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        return self.clients.get(client_id)

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        self.clients[client_info.client_id] = client_info
        self._save()

    # --- Yetkilendirme ---

    async def authorize(self, client: OAuthClientInformationFull, params: AuthorizationParams) -> str:
        """Kullanıcıyı Cockpit giriş sayfasına yönlendirir."""
        now = time.time()
        self.pending = {k: v for k, v in self.pending.items() if v[2] > now}
        request_id = secrets.token_urlsafe(24)
        self.pending[request_id] = (client.client_id, params, now + LOGIN_REQUEST_TTL)
        return f"{self.login_url}?request={request_id}"

    def pending_client_name(self, request_id: str) -> str | None:
        entry = self.pending.get(request_id)
        if not entry or entry[2] < time.time():
            return None
        client = self.clients.get(entry[0])
        return (client.client_name if client else None) or entry[0]

    def pending_resource(self, request_id: str) -> str | None:
        """Bekleyen yetkilendirme isteğinin RFC 8707 resource değeri (istemcinin bağlandığı URL)."""
        entry = self.pending.get(request_id)
        return entry[1].resource if entry else None

    def complete_authorization(self, request_id: str, username: str) -> str | None:
        """Başarılı Cockpit girişinden sonra istemcinin redirect adresini (code ile) döner."""
        entry = self.pending.pop(request_id, None)
        if not entry or entry[2] < time.time():
            return None
        client_id, params, _ = entry
        code = secrets.token_urlsafe(32)
        self.codes[code] = AuthorizationCode(
            code=code,
            scopes=params.scopes or [SCOPE],
            expires_at=time.time() + AUTH_CODE_TTL,
            client_id=client_id,
            code_challenge=params.code_challenge,
            redirect_uri=params.redirect_uri,
            redirect_uri_provided_explicitly=params.redirect_uri_provided_explicitly,
            resource=params.resource,
            subject=username,
        )
        return construct_redirect_uri(str(params.redirect_uri), code=code, state=params.state)

    def deny_authorization(self, request_id: str) -> str | None:
        entry = self.pending.pop(request_id, None)
        if not entry:
            return None
        params = entry[1]
        return construct_redirect_uri(str(params.redirect_uri), error="access_denied", state=params.state)

    async def load_authorization_code(self, client: OAuthClientInformationFull, authorization_code: str):
        code = self.codes.get(authorization_code)
        if code and code.client_id == client.client_id:
            return code
        return None

    # --- Token'lar ---

    def _issue(self, client_id: str, scopes: list[str], subject: str | None, resource: str | None) -> OAuthToken:
        access, refresh = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        now = int(time.time())
        self.access_tokens[_hash(access)] = AccessToken(
            token=_hash(access), client_id=client_id, scopes=scopes,
            expires_at=now + ACCESS_TOKEN_TTL, resource=resource, subject=subject,
        )
        self.refresh_tokens[_hash(refresh)] = RefreshToken(
            token=_hash(refresh), client_id=client_id, scopes=scopes,
            expires_at=now + REFRESH_TOKEN_TTL, resource=resource, subject=subject,
        )
        self._save()
        return OAuthToken(
            access_token=access, token_type="Bearer", expires_in=ACCESS_TOKEN_TTL,
            refresh_token=refresh, scope=" ".join(scopes),
        )

    async def exchange_authorization_code(self, client: OAuthClientInformationFull, authorization_code) -> OAuthToken:
        if self.codes.pop(authorization_code.code, None) is None:
            raise TokenError("invalid_grant", "authorization code already used")
        return self._issue(client.client_id, authorization_code.scopes, authorization_code.subject,
                           authorization_code.resource)

    async def load_refresh_token(self, client: OAuthClientInformationFull, refresh_token: str):
        token = self.refresh_tokens.get(_hash(refresh_token))
        if token and token.client_id == client.client_id:
            return token
        return None

    async def exchange_refresh_token(self, client: OAuthClientInformationFull, refresh_token, scopes: list[str]) -> OAuthToken:
        # Refresh token tek kullanımlık: yenisi verilir, eskisi silinir
        self.refresh_tokens.pop(refresh_token.token, None)
        return self._issue(client.client_id, scopes or refresh_token.scopes, refresh_token.subject,
                           refresh_token.resource)

    async def load_access_token(self, token: str) -> AccessToken | None:
        access = self.access_tokens.get(_hash(token))
        if access and access.expires_at and access.expires_at < time.time():
            return None
        return access

    async def revoke_token(self, token: Any) -> None:
        self.access_tokens.pop(token.token, None)
        self.refresh_tokens.pop(token.token, None)
        self._save()
