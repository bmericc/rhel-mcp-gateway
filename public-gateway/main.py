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

class ServerModel(BaseModel):
    name: str
    host: str
    port: int = 22
    user: str = "root"
    ssh_key_path: str = "/root/.ssh/id_rsa"

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
        f"<li><b>{s['name']}</b> ({s['user']}@{s['host']}:{s.get('port', 22)}) - Key: {s['ssh_key_path']}</li>" 
        for s in servers.values()
    ]) if servers else "<li>Henüz tanımlı sunucu yok.</li>"
    
    return f"""
        <h2>Hoş geldiniz, {user.get('email')}!</h2>
        <p>MCP Gateway aktif (Port: 7435).</p>
        <h3>Kayıtlı Sunucular (Hafıza):</h3>
        <ul>{servers_html}</ul>
        <hr>
        <h4>Yeni Sunucu Ekle:</h4>
        <form action="/add-server" method="POST" style="display:flex; flex-direction:column; width:300px; gap:8px;">
            <input type="text" name="name" placeholder="Sunucu Adı (örn: prod-db)" required>
            <input type="text" name="host" placeholder="IP veya Domain" required>
            <input type="number" name="port" value="22" placeholder="SSH Port">
            <input type="text" name="user" value="root" placeholder="Kullanıcı Adı">
            <input type="text" name="ssh_key_path" value="/root/.ssh/id_rsa" placeholder="RSA Key Yolu">
            <button type="submit">Sunucuyu Kaydet</button>
        </form>
        <br><a href="/logout">Çıkış Yap</a>
    """

@app.post("/add-server")
async def add_server_form(request: Request):
    form = await request.form()
    servers = load_servers()
    name = form.get("name")
    
    servers[name] = {
        "name": name,
        "host": form.get("host"),
        "port": int(form.get("port", 22)),
        "user": form.get("user", "root"),
        "ssh_key_path": form.get("ssh_key_path", "/root/.ssh/id_rsa")
    }
    save_servers(servers)
    return RedirectResponse(url='/', status_code=303)

@app.post("/api/servers")
async def api_add_server(server: ServerModel):
    servers = load_servers()
    servers[server.name] = server.dict()
    save_servers(servers)
    return {"status": "success", "message": f"'{server.name}' başarıyla kaydedildi."}

@app.get("/api/servers")
async def api_list_servers():
    return load_servers()

@app.post("/api/run-command")
async def api_run_command(data: dict):
    server_name = data.get("server_name")
    command = data.get("command")
    
    servers = load_servers()
    if server_name not in servers:
        raise HTTPException(status_code=404, detail="Sunucu hafızada bulunamadı.")
    
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
            return {
                "server": server_name,
                "exit_status": result.exit_status,
                "stdout": result.stdout,
                "stderr": result.stderr
            }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"SSH Bağlantı Hatası: {str(e)}")

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

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 7435))
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=False)
