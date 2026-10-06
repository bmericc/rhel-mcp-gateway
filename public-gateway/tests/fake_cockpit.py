"""Testler için cockpit-ws taklidi.

Mesaj biçimleri, gerçek cockpit-ws 362 ile yapılan denemelerde görülen davranışa göre yazıldı:
- giriş: GET /cockpit/login + HTTP Basic -> "cockpit" çerezi, hatalı şifrede 401
- WebSocket /cockpit/socket, alt protokol "cockpit1", ilk mesaj sunucudan "init"
- stream kanalı: ready -> veri -> done -> close{exit-status, message}
- bulunamayan komut: close{problem: not-found}
- superuser: require ve kullanıcının sudo yetkisi yoksa close{problem: terminated}
"""
import asyncio
import base64
import json
import socket
import threading
import time

import uvicorn
from creds import PASSWORD
from starlette.applications import Starlette
from starlette.responses import JSONResponse, Response
from starlette.routing import Route, WebSocketRoute
from starlette.websockets import WebSocket

USERS = {"admin": (PASSWORD, True), "plain": (PASSWORD, False)}  # kullanıcı: (şifre, sudo yetkisi)
COOKIE = "fake-session"


class FakeCockpit:
    def __init__(self):
        self.logins = []
        self.opened = []  # gelen "open" mesajları
        self.session_user = None
        self.app = Starlette(routes=[
            Route("/cockpit/login", self.login),
            WebSocketRoute("/cockpit/socket", self.socket),
        ])

    async def login(self, request):
        header = request.headers.get("authorization", "")
        user, password = "", ""
        if header.startswith("Basic "):
            user, _, password = base64.b64decode(header[6:]).decode().partition(":")
        self.logins.append({"user": user, "superuser": request.headers.get("x-superuser")})
        if USERS.get(user, (None,))[0] != password:
            return Response("Authentication failed", status_code=401)
        self.session_user = user
        resp = JSONResponse({"csrf-token": "x"})
        resp.set_cookie("cockpit", f"{COOKIE}-{user}")
        return resp

    async def socket(self, ws: WebSocket):
        if not ws.cookies.get("cockpit", "").startswith(COOKIE) or "cockpit1" not in ws.scope.get("subprotocols", []):
            await ws.close(code=1008)
            return
        user = ws.cookies["cockpit"][len(COOKIE) + 1:]
        await ws.accept(subprotocol="cockpit1")
        await ws.send_text("\n" + json.dumps({"command": "init", "version": 1, "channel-seed": "1:", "host": "localhost"}))
        client_init = json.loads((await ws.receive_text()).partition("\n")[2])
        assert client_init["command"] == "init"
        while True:
            try:
                raw = await ws.receive_text()
            except Exception:
                return
            channel, _, payload = raw.partition("\n")
            if channel != "":
                continue
            msg = json.loads(payload)
            if msg.get("command") == "open":
                self.opened.append(msg)
                await self._run(ws, user, msg)

    async def _run(self, ws, user, msg):
        ch, argv = msg["channel"], msg["spawn"]

        async def control(**kw):
            await ws.send_text("\n" + json.dumps({"channel": ch, **kw}))

        if msg.get("superuser") == "require" and not USERS[user][1]:
            await control(command="close", problem="terminated", message="Peer exited with status 1")
            return
        cmd = argv[0]
        if cmd == "missing":
            await control(command="close", problem="not-found")
            return
        if cmd == "sleep":
            return  # hiç kapanmaz; istemci zaman aşımı uygulamalı
        await control(command="ready", pid=1)
        if cmd == "id":
            out, status, err = ("0\n" if msg.get("superuser") else "1000\n"), 0, ""
        elif cmd == "fail":
            out, status, err = "partial\n", 3, "err\n"
        elif cmd == "sh":
            out, status, err = f"sh:{argv[2]}\n", 0, ""
        else:
            out, status, err = " ".join(argv) + "\n", 0, ""
        # Gerçek cockpit büyük çıktıyı parça parça gönderir
        for part in (out[: len(out) // 2], out[len(out) // 2:]):
            if part:
                await ws.send_text(f"{ch}\n{part}")
        await control(command="done")
        await control(command="close", **{"exit-status": status, "message": err})


class LiveFakeCockpit:
    def __init__(self):
        self.fake = FakeCockpit()
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            self.port = s.getsockname()[1]
        self.url = f"http://127.0.0.1:{self.port}"
        self.server = uvicorn.Server(uvicorn.Config(self.fake.app, host="127.0.0.1", port=self.port, log_level="error"))
        self.thread = threading.Thread(target=self.server.run, daemon=True)

    def start(self):
        self.thread.start()
        deadline = time.time() + 10
        while not self.server.started:
            if time.time() > deadline:
                raise RuntimeError("sahte cockpit başlamadı")
            time.sleep(0.05)
        return self

    def stop(self):
        self.server.should_exit = True
        self.thread.join(timeout=10)
