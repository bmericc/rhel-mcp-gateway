import os
import json
import asyncio
from typing import Dict, Any
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from pydantic import BaseModel
from starlette.middleware.sessions import SessionMiddleware
from authlib.integrations.starlette_client import OAuth
import asyncssh

# MCP Kütüphaneleri
from mcp.server import Server
import mcp.types as types
from mcp.server.sse import SsseServerTransport # Veya standart sse transport

app = FastAPI()

app.add_middleware(
    SessionMiddleware, 
    secret_key=os.getenv("SECRET_KEY", "gizli-anahtar")
)

oauth = OAuth()
oauth.register(
    name='google',
    client_id=os.getenv("GOOGLE_CLIENT_ID", ""),
    client_secret=os.getenv("GOOGLE_CLIENT_SECRET", ""),
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'}
)

SERVERS_FILE = "data/servers.json"

def load_servers() -> Dict[str, Dict[str, Any]]:
    os.makedirs(os.path.dirname(SERVERS_FILE), exist_ok=True)
    if os.path.exists(SERVERS_FILE):
        try:
            with open(SERVERS_FILE, "r") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}

def save_servers(servers: Dict[str, Dict[str, Any]]):
    os.makedirs(os.path.dirname(SERVERS_FILE), exist_ok=True)
    with open(SERVERS_FILE, "w") as f:
        json.dump(servers, f, indent=4)

# --- MCP Sunucu Tanımları ---
mcp_server = Server("rhel-fleet-gateway")

@mcp_server.list_tools()
async def handle_list_tools() -> list[types.Tool]:
    return [
        types.Tool(
            name="list_servers",
            description="Hafızada kayıtlı olan tüm RHEL sunucularını listeler.",
            inputSchema={"type": "object", "properties": {}}
        ),
        types.Tool(
            name="run_remote_command",
            description="Kayıtlı bir uzak RHEL sunucusunda RSA key ile güvenli bir komut çalıştırır.",
            inputSchema={
                "type": "object",
                "properties": {
                    "server_name": {"type": "string", "description": "Sunucu adı (örn: prod-db)"},
                    "command": {"type": "string", "description": "Çalıştırılacak Linux komutu (örn: systemctl status nginx)"}
                },
                "required": ["server_name", "command"]
            }
        )
    ]

@mcp_server.call_tool()
async def handle_call_tool(name: str, arguments: dict) -> list[types.TextContent]:
    servers = load_servers()
    
    if name == "list_servers":
        return [types.TextContent(type="text", text=json.dumps(servers, indent=4))]

    elif name == "run_remote_command":
        server_name = arguments.get("server_name")
        command = arguments.get("command")
        
        if server_name not in servers:
            return [types.TextContent(type="text", text=f"Hata: '{server_name}' sunucusu hafızada bulunamadı.")]
        
        cfg = servers[server_name]
        try:
            async with asyncssh.connect(
                cfg["host"], 
                port=cfg.get("port", 22), 
                username=cfg["user"], 
                client_keys=[cfg["ssh_key_path"]], 
                known_hosts=None
            ) as conn:
                result = await conn.run(command, check=False)
                output = f"Exit Status: {result.exit_status}\nStdout:\n{result.stdout}\nStderr:\n{result.stderr}"
                return [types.TextContent(type="text", text=output)]
        except Exception as e:
            return [types.TextContent(type="text", text=f"SSH Bağlantı Hatası: {str(e)}")]

# FastAPI Web Uç Noktaları
@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    user = request.session.get('user')
    if not user:
        return """
        <h2>RHEL MCP Gateway - Giriş Yapın</h2>
        <a href="/login" style="padding: 10px 20px; background: #4285F4; color: white; text-decoration: none; border-radius: 5px;">Google ile Giriş Yap</a>
        """
    
    servers = load_servers()
    servers_html = "".join([
        f"<li><b>{s['name']}</b> ({s['user']}@{s['host']}:{s.get('port', 22)})</li>" 
        for s in servers.values()
    ]) if servers else "<li>Henüz tanımlı sunucu yok.</li>"
    
    return f"""
        <h2>Hoş geldiniz, {user.get('email')}!</h2>
        <p>MCP Gateway aktif. SSE Uç Noktası: <code>https://mcp.kalehost.net/sse</code></p>
        <h3>Kayıtlı Sunucular:</h3>
        <ul>{servers_html}</ul>
        <br><a href="/logout">Çıkış Yap</a>
    """

@app.get("/login")
async def login(request: Request):
    redirect_uri = request.url_for('auth')
    return await oauth.google.authorize_redirect(request, redirect_uri)

@app.get("/auth")
async def auth(request: Request):
    token = await oauth.google.authorize_access_token(request)
    user = token.get('userinfo')
    if not user:
        user = await oauth.google.parse_id_token(request, token)
    request.session['user'] = dict(user)
    return RedirectResponse(url='/', status_code=303)

@app.get("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse(url='/', status_code=303)

# --- MCP SSE Transport Entegrasyonu ---
from mcp.server.sse import SseServerTransport
from starlette.routing import Mount, Route

sse = SseServerTransport("/messages")

async def handle_sse(request: Request):
    async with sse.connect_sse(
        request.scope, request.receive, request._send
    ) as streams:
        await mcp_server.run(
            streams[0], streams[1], mcp_server.create_initialization_options()
        )

# FastAPI route'larına MCP SSE ekleme
app.routes.append(Route("/sse", endpoint=handle_sse))
app.routes.append(Mount("/messages", app=sse.handle_post_message))

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 7435))
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=False)
