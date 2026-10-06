import asyncio
import websockets
import subprocess
import json
import os

GATEWAY_URL = os.getenv("GATEWAY_URL", "ws://sizin-public-sunucu-ip:7435/ws/agent?agent_id=kurumsal-rhel-01")

async def run_agent():
    while True:
        try:
            print(f"[*] Gateway'e bağlanılıyor: {GATEWAY_URL}")
            async with websockets.connect(GATEWAY_URL) as websocket:
                print("[✔] Gateway bağlantısı başarılı. Komut bekleniyor...")
                while True:
                    message = await websocket.recv()
                    data = json.loads(message)
                    cmd_id = data.get("id")
                    command = data.get("command")
                    
                    print(f"[>] Komut çalıştırılıyor: {command}")
                    
                    proc = await asyncio.create_subprocess_shell(
                        command,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE
                    )
                    stdout, stderr = await proc.communicate()
                    
                    response = {
                        "id": cmd_id,
                        "stdout": stdout.decode("utf-8", errors="ignore"),
                        "stderr": stderr.decode("utf-8", errors="ignore"),
                        "exit_code": proc.returncode
                    }
                    await websocket.send(json.dumps(response))
        except Exception as e:
            print(f"[!] Bağlantı hatası: {e}. 5 saniye sonra yeniden denenecek...")
            await asyncio.sleep(5)

if __name__ == "__main__":
    asyncio.run(run_agent())
