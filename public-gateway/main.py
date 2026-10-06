import os
import json
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from starlette.middleware.sessions import SessionMiddleware
from authlib.integrations.starlette_client import OAuth

app = FastAPI()

# Oturum yönetimi için Secret Key (Docker env üzerinden alınır)
app.add_middleware(
    SessionMiddleware, 
    secret_key=os.getenv("SECRET_KEY", "gizli-ve-guvenli-anahtar")
)

oauth = OAuth()
oauth.register(
    name='google',
    client_id=os.getenv("GOOGLE_CLIENT_ID", ""),
    client_secret=os.getenv("GOOGLE_CLIENT_SECRET", ""),
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'}
)

# Bağlı olan iç ağ ajanlarının listesi: {agent_id: WebSocket}
active_agents: dict[str, WebSocket] = {}

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    user = request.session.get('user')
    if not user:
        return """
        <h2>RHEL MCP Gateway - Giriş Yapın</h2>
        <a href="/login" style="padding: 10px 20px; background: #4285F4; color: white; text-decoration: none; border-radius: 5px;">Google ile Giriş Yap</a>
        """
    
    agent_list = list(active_agents.keys())
    agents_html = "".join([f"<li>{agent} (Aktif)</li>" for agent in agent_list]) if agent_list else "<li>Aktif ajan yok.</li>"
    
    return f"""
        <h2>Hoş geldiniz, {user.get('email')}!</h2>
        <p>MCP Gateway aktif ve çalışıyor.</p>
        <h3>Bağlı İç Ağ Ajanları:</h3>
        <ul>{agents_html}</ul>
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

# İç ağdaki ajanların public sunucuya bağlanacağı WebSocket uç noktası
@app.websocket("/ws/agent")
async def agent_websocket(websocket: WebSocket, agent_id: str = "default-rhel-node"):
    await websocket.accept()
    active_agents[agent_id] = websocket
    print(f"[+] İç ağ ajanı bağlandı: {agent_id}")
    try:
        while True:
            data = await websocket.receive_text()
            # Ajanlardan gelen komut yanıtları burada işlenir
            print(f"[-] Ajan yanıtı [{agent_id}]: {data}")
    except WebSocketDisconnect:
        del active_agents[agent_id]
        print(f"[!] Ajan bağlantısı koptu: {agent_id}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=80, reload=False)
