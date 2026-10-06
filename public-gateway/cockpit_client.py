"""Cockpit (cockpit-ws) istemcisi.

Akış:
  1. GET /cockpit/login (HTTP Basic + "X-Superuser: any") -> "cockpit" çerezi
  2. /cockpit/socket adresine "cockpit1" alt protokolüyle WebSocket
  3. Sunucunun "init" mesajına "init" ile cevap
  4. Her komut için bir "stream" kanalı: open -> done -> (veri) -> close

Mesaj biçimi "<kanal>\\n<içerik>"; kontrol mesajları boş kanal adıyla JSON olarak gelir.
"""
import asyncio
import itertools
import json
import ssl
from typing import Any

import httpx
import websockets

from fleet_tools import CommandResult


class CockpitError(Exception):
    """Cockpit'e bağlanılamadı veya giriş yapılamadı (SSH'a geçmek için sebep)."""


class CockpitSession:
    def __init__(self, url: str, user: str, password: str, verify_tls: bool = False, connect_timeout: float = 10):
        self.url = url.rstrip("/")
        self.user = user
        self.password = password
        self.verify_tls = verify_tls
        self.connect_timeout = connect_timeout
        self._ws = None
        self._reader = None
        self._channels: dict[str, asyncio.Queue] = {}
        self._ids = itertools.count(1)
        self._closed_reason: str | None = None

    def _ssl_context(self):
        if not self.url.startswith("https://"):
            return None
        ctx = ssl.create_default_context()
        if not self.verify_tls:
            # Cockpit çoğunlukla kendinden imzalı sertifika kullanır
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        return ctx

    async def connect(self):
        try:
            async with httpx.AsyncClient(verify=self._ssl_context() or True, trust_env=False,
                                         timeout=self.connect_timeout) as client:
                resp = await client.get(
                    f"{self.url}/cockpit/login",
                    auth=(self.user, self.password),
                    # Yetki gerektiren işlemler için giriş şifresi sudo'da yeniden kullanılır
                    headers={"X-Superuser": "any"},
                )
        except httpx.HTTPError as e:
            raise CockpitError(f"Cockpit'e bağlanılamadı ({self.url}): {e}") from e
        if resp.status_code == 401:
            raise CockpitError(f"Cockpit girişi reddedildi ({self.user}@{self.url})")
        if resp.status_code != 200 or "cockpit" not in resp.cookies:
            raise CockpitError(f"Cockpit girişi başarısız ({self.url}): HTTP {resp.status_code}")

        ws_url = "ws" + self.url[len("http"):] + "/cockpit/socket"
        try:
            self._ws = await asyncio.wait_for(websockets.connect(
                ws_url,
                subprotocols=["cockpit1"],
                additional_headers={"Cookie": f"cockpit={resp.cookies['cockpit']}", "Origin": self.url},
                ssl=self._ssl_context(),
                proxy=None,
                max_size=None,
            ), self.connect_timeout)
            init = await asyncio.wait_for(self._ws.recv(), self.connect_timeout)
        except Exception as e:
            await self.close()
            raise CockpitError(f"Cockpit WebSocket bağlantısı kurulamadı ({ws_url}): {e}") from e

        channel, payload = _split(init)
        message = json.loads(payload) if channel == "" else {}
        if message.get("command") != "init":
            await self.close()
            raise CockpitError(f"Cockpit beklenmeyen ilk mesaj gönderdi: {payload[:200]}")
        if message.get("problem"):
            await self.close()
            raise CockpitError(f"Cockpit oturumu açılamadı: {message['problem']}")

        await self._send("", {"command": "init", "version": 1, "host": "localhost"})
        self._reader = asyncio.create_task(self._read_loop())
        return self

    async def close(self):
        if self._reader:
            self._reader.cancel()
            self._reader = None
        if self._ws is not None:
            try:
                await self._ws.close()
            except Exception:
                pass
            self._ws = None

    async def __aenter__(self):
        return await self.connect()

    async def __aexit__(self, *exc):
        await self.close()

    async def _send(self, channel: str, payload: Any):
        text = payload if isinstance(payload, str) else json.dumps(payload)
        await self._ws.send(f"{channel}\n{text}")

    async def _read_loop(self):
        try:
            async for raw in self._ws:
                channel, payload = _split(raw)
                if channel == "":
                    message = json.loads(payload)
                    target = message.get("channel")
                    if target in self._channels:
                        self._channels[target].put_nowait(("control", message))
                    elif message.get("command") == "close" and not target:
                        self._fail_all(message.get("problem") or "disconnected")
                        return
                elif channel in self._channels:
                    self._channels[channel].put_nowait(("data", payload))
        except asyncio.CancelledError:
            raise
        except Exception as e:
            self._fail_all(str(e))
            return
        self._fail_all("bağlantı kapandı")

    def _fail_all(self, reason: str):
        self._closed_reason = reason
        for queue in self._channels.values():
            queue.put_nowait(("control", {"command": "close", "problem": "disconnected", "message": reason}))

    async def spawn(self, argv: list[str], superuser: bool = False, timeout: float = 60) -> CommandResult:
        if self._ws is None or self._closed_reason:
            raise CockpitError(f"Cockpit bağlantısı kapalı: {self._closed_reason}")

        channel = f"mcp{next(self._ids)}"
        queue: asyncio.Queue = asyncio.Queue()
        self._channels[channel] = queue
        options = {
            "command": "open",
            "channel": channel,
            "payload": "stream",
            "spawn": argv,
            "err": "message",
            # Çıktıların ayrıştırılabilmesi için dil ayarını sabitle
            "environ": ["LC_ALL=C"],
        }
        if superuser:
            options["superuser"] = "require"

        stdout: list[str] = []
        try:
            await self._send("", options)
            # Komut stdin beklemesin
            await self._send("", {"command": "done", "channel": channel})

            async def collect():
                while True:
                    kind, item = await queue.get()
                    if kind == "data":
                        stdout.append(item)
                    elif item.get("command") == "close":
                        return item

            try:
                closing = await asyncio.wait_for(collect(), timeout)
            except asyncio.TimeoutError:
                await self._send("", {"command": "close", "channel": channel})
                return CommandResult(self.user, None, "".join(stdout),
                                     f"Komut {timeout} saniyede zaman aşımına uğradı.", "cockpit")
        finally:
            self._channels.pop(channel, None)

        if closing.get("problem") == "disconnected":
            raise CockpitError(f"Cockpit bağlantısı koptu: {closing.get('message')}")

        stderr = closing.get("message", "")
        problem = closing.get("problem")
        if "exit-status" in closing:
            exit_status = closing["exit-status"]
        elif "exit-signal" in closing:
            exit_status = None
            stderr = (stderr + f"\nSinyal ile sonlandı: {closing['exit-signal']}").strip()
        else:
            exit_status = None
        if problem:
            hint = {
                "not-found": "komut bulunamadı",
                "access-denied": "yetki reddedildi",
            }.get(problem, "")
            if superuser and problem == "terminated":
                hint = "yönetici yetkisi alınamadı (kullanıcının sudo yetkisi olmalı)"
            stderr = (f"Cockpit hatası: {problem}" + (f" ({hint})" if hint else "") + (f"\n{stderr}" if stderr else ""))
        return CommandResult(self.user, exit_status, "".join(stdout), stderr, "cockpit")


def _split(raw) -> tuple[str, str]:
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", errors="replace")
    channel, _, payload = raw.partition("\n")
    return channel, payload
