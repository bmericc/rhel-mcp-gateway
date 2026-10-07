"""İşlem kaydı (audit log).

Gateway üzerinden yapılan her işlem (MCP araç çağrıları, panel işlemleri, girişler) bir JSON
satırı olarak dosyaya eklenir. Dosya büyüyünce `.1` uzantısıyla yedeklenir ve yenisi başlatılır.
Şifreler ve anahtarlar kaydedilmez; çalıştırılan komutlar ve çıktıları (kırpılarak) kaydedilir.
"""
import json
import os
import sys
import time
from typing import Any

LOG_FILE = "data/audit.log"
MAX_BYTES = int(float(os.getenv("AUDIT_LOG_MAX_MB", "10")) * 1024 * 1024)
# Tek bir alanın (örn. komut çıktısı) kayıtta kaplayabileceği en fazla karakter
MAX_FIELD_CHARS = 4000


def clip(value: Any, limit: int = MAX_FIELD_CHARS) -> Any:
    if isinstance(value, str) and len(value) > limit:
        return value[:limit] + f"… [truncated, {len(value)} characters total]"
    if isinstance(value, dict):
        return {k: clip(v, limit) for k, v in value.items()}
    if isinstance(value, list):
        return [clip(v, limit) for v in value]
    return value


def _rotate():
    try:
        if os.path.getsize(LOG_FILE) >= MAX_BYTES:
            os.replace(LOG_FILE, LOG_FILE + ".1")
    except OSError:
        pass


def record(source: str, action: str, status: str = "ok", **fields: Any) -> None:
    """Bir işlemi kaydeder. status: "ok" | "error" | "preview" (onay bekleyen araç çağrısı).

    Boş (None / "") alanlar yazılmaz. Kayıt yazılamazsa işlem bozulmaz; hata stderr'e düşer.
    """
    entry = {"at": time.strftime("%Y-%m-%d %H:%M:%S"), "source": source, "action": action, "status": status}
    entry.update({k: clip(v) for k, v in fields.items() if v not in (None, "", [], {})})
    try:
        os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
        _rotate()
        fd = os.open(LOG_FILE, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False, default=str) + "\n")
    except OSError as e:
        print(f"could not write audit log: {e}", file=sys.stderr)


def _lines_newest_first():
    for path in (LOG_FILE, LOG_FILE + ".1"):
        try:
            with open(path, encoding="utf-8") as f:
                lines = f.readlines()
        except OSError:
            continue
        yield from reversed(lines)


def read(limit: int = 100, offset: int = 0, q: str = "", **filters: str) -> tuple[list[dict], bool]:
    """En yeni kayıt başta olacak şekilde (kayıtlar, daha eskisi var mı) döner.

    filters: alan adı -> tam eşleşmesi istenen değer (boş olanlar yok sayılır).
    q: kaydın herhangi bir yerinde geçen metin (büyük/küçük harf duyarsız).
    """
    filters = {k: v for k, v in filters.items() if v}
    needle = q.casefold().strip()
    entries: list[dict] = []
    skipped = 0
    for line in _lines_newest_first():
        if needle and needle not in line.casefold():
            continue
        try:
            entry = json.loads(line)
        except ValueError:
            continue
        if any(str(entry.get(k, "")) != v for k, v in filters.items()):
            continue
        if skipped < offset:
            skipped += 1
            continue
        if len(entries) == limit:
            return entries, True
        entries.append(entry)
    return entries, False
