"""Testler için asgari HTTP CONNECT / SOCKS5 proxy'si (asyncio, ek paket yok).

Bağlantı isteklerini kaydeder ve veriyi hedefle istemci arasında aktarır.
"""
import asyncio
import base64
import socket
import struct
import threading


class FakeProxy:
    def __init__(self, kind: str, username: str | None = None, password: str | None = None):
        self.kind = kind  # "http" veya "socks5"
        self.username = username
        self.password = password
        self.targets: list[tuple[str, int]] = []
        self.loop = asyncio.new_event_loop()
        self.server = None
        self.port = None
        self.thread = threading.Thread(target=self.loop.run_forever, daemon=True)

    def url(self, scheme: str | None = None, auth: tuple[str, str] | None = None) -> str:
        cred = f"{auth[0]}:{auth[1]}@" if auth else ""
        return f"{scheme or self.kind}://{cred}127.0.0.1:{self.port}"

    def start(self):
        self.thread.start()
        future = asyncio.run_coroutine_threadsafe(asyncio.start_server(self._handle, "127.0.0.1", 0), self.loop)
        self.server = future.result(5)
        self.port = self.server.sockets[0].getsockname()[1]
        return self

    def stop(self):
        async def shutdown():
            self.server.close()
        asyncio.run_coroutine_threadsafe(shutdown(), self.loop).result(5)
        self.loop.call_soon_threadsafe(self.loop.stop)
        self.thread.join(5)

    async def _handle(self, reader, writer):
        try:
            target = await (self._http(reader, writer) if self.kind == "http" else self._socks5(reader, writer))
            if target is None:
                return
            host, port, ok, fail = target
            self.targets.append((host, port))
            try:
                up_reader, up_writer = await asyncio.open_connection(host, port)
            except OSError:
                writer.write(fail)
                await writer.drain()
                writer.close()
                return
            writer.write(ok)
            await writer.drain()

            async def pipe(src, dst):
                try:
                    while data := await src.read(65536):
                        dst.write(data)
                        await dst.drain()
                except Exception:
                    pass
                finally:
                    dst.close()

            await asyncio.gather(pipe(reader, up_writer), pipe(up_reader, writer))
        except Exception:
            writer.close()

    async def _http(self, reader, writer):
        head = await reader.readuntil(b"\r\n\r\n")
        lines = head.decode().split("\r\n")
        method, target, _ = lines[0].split(" ")
        headers = {k.strip().lower(): v.strip() for k, _, v in (l.partition(":") for l in lines[1:] if l)}
        if self.username:
            expected = "Basic " + base64.b64encode(f"{self.username}:{self.password}".encode()).decode()
            if headers.get("proxy-authorization") != expected:
                writer.write(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
                await writer.drain()
                writer.close()
                return None
        host, _, port = target.rpartition(":")
        return host.strip("[]"), int(port), b"HTTP/1.1 200 Connection established\r\n\r\n", b"HTTP/1.1 502 Bad Gateway\r\n\r\n"

    async def _socks5(self, reader, writer):
        version, count = await reader.readexactly(2)
        methods = await reader.readexactly(count)
        wanted = 2 if self.username else 0
        if wanted not in methods:
            writer.write(b"\x05\xff")
            await writer.drain()
            writer.close()
            return None
        writer.write(bytes([5, wanted]))
        if wanted == 2:
            _, ulen = await reader.readexactly(2)
            user = (await reader.readexactly(ulen)).decode()
            (plen,) = await reader.readexactly(1)
            password = (await reader.readexactly(plen)).decode()
            ok = user == self.username and password == self.password
            writer.write(b"\x01\x00" if ok else b"\x01\x01")
            if not ok:
                await writer.drain()
                writer.close()
                return None
        _, cmd, _, atype = await reader.readexactly(4)
        if atype == 1:
            host = socket.inet_ntop(socket.AF_INET, await reader.readexactly(4))
        elif atype == 4:
            host = socket.inet_ntop(socket.AF_INET6, await reader.readexactly(16))
        else:
            (length,) = await reader.readexactly(1)
            host = (await reader.readexactly(length)).decode()
        (port,) = struct.unpack(">H", await reader.readexactly(2))
        ok = b"\x05\x00\x00\x01" + socket.inet_aton("127.0.0.1") + struct.pack(">H", 0)
        fail = b"\x05\x05\x00\x01" + socket.inet_aton("0.0.0.0") + struct.pack(">H", 0)
        return host, port, ok, fail
