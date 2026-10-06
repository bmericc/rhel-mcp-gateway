# RHEL MCP Gateway

[![tests](https://github.com/bmericc/rhel-mcp-gateway/actions/workflows/tests.yml/badge.svg)](https://github.com/bmericc/rhel-mcp-gateway/actions/workflows/tests.yml)

RHEL sunucu filosunu [Model Context Protocol (MCP)](https://modelcontextprotocol.io) üzerinden yapay zekâ asistanlarına (Claude vb.) açan bir gateway. Asistan, kayıtlı sunucuları listeleyebilir ve bu sunucularda SSH ile komut çalıştırabilir.

```
MCP client (Claude)  ──SSE──▶  public-gateway (FastAPI, :7435)  ──SSH──▶  RHEL sunucuları
                                     │
                                     └── data/servers.json (kayıtlı sunucular)
```

## Bileşenler

| Klasör | Açıklama |
| --- | --- |
| `public-gateway/` | MCP SSE sunucusu, Google OAuth ile giriş yapılan basit web paneli ve SSH istemcisi |
| `internal-agent/` | WebSocket üzerinden gateway'e bağlanıp komut çalıştırması planlanan ajan. **Henüz kullanılmıyor:** gateway'de `/ws/agent` uç noktası yok. |

## Kurulum

```bash
cp sample.env .env      # değerleri düzenleyin
docker compose up -d --build
```

Gateway `7435` portunda çalışır. Üretimde önüne HTTPS sonlandıran bir reverse proxy (nginx, Caddy vb.) koyun. Uygulama `X-Forwarded-*` başlıklarını dikkate alır.

### Ortam değişkenleri (`.env`)

| Değişken | Açıklama |
| --- | --- |
| `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` | Web paneline giriş için Google OAuth bilgileri. Yönlendirme adresi: `https://<alan-adınız>/auth` |
| `SECRET_KEY` | Oturum çerezlerini imzalamak için rastgele bir değer |
| `PORT` | Dinlenecek port (varsayılan `7435`) |
| `MCP_API_KEY` | `/sse` uç noktasını koruyan token. **Tanımlanmazsa `/sse` herkese açık olur** ve URL'yi bilen herkes kayıtlı sunucularda komut çalıştırabilir. |
| `SSH_LOGINS` | Denenecek SSH kullanıcıları ve key klasörleri, sırasıyla. Varsayılan: `root:/root/.ssh,bmericc:/home/bmericc/.ssh` |

`docker-compose.yml`, `/root/.ssh` ve `/home/bmericc/.ssh` klasörlerini konteynere salt okunur olarak bağlar. `SSH_LOGINS`'e başka bir kullanıcı eklerseniz o kullanıcının `.ssh` klasörünü de compose dosyasına ekleyin.

## Sunucu tanımlama

Sunucular `data/servers.json` dosyasında tutulur. Bu dosya git'e alınmaz.

```json
{
    "prod-db": {
        "name": "prod-db",
        "host": "192.168.0.98",
        "port": 22,
        "user": "bmericc"
    },
    "web-01": {
        "name": "web-01",
        "host": "10.0.0.12",
        "user": "root",
        "ssh_key_path": "/root/.ssh/id_rsa"
    }
}
```

| Alan | Zorunlu | Açıklama |
| --- | --- | --- |
| `name` | evet | Sunucu adı (anahtar ile aynı olmalı) |
| `host` | evet | IP veya alan adı |
| `port` | hayır | SSH portu, varsayılan `22` |
| `user` | hayır | İlk denenecek kullanıcı |
| `ssh_key_path` | hayır | `user` için kullanılacak key. Verilmezse o kullanıcının `SSH_LOGINS`'teki klasöründe `id_ed25519`, `id_ecdsa`, `id_rsa` sırasıyla aranır. |

### SSH giriş sırası

1. Sunucuya tanımlı `user` (varsa)
2. `SSH_LOGINS`'teki diğer kullanıcılar, sırayla

Bir sonraki kullanıcıya yalnızca kimlik doğrulama reddedildiğinde geçilir. Bağlantı reddi, zaman aşımı gibi ağ hatalarında hemen hata döner. Komut çıktısında hangi kullanıcıyla bağlanıldığı yazar (`User: bmericc`).

## MCP araçları

| Araç | Parametreler | Açıklama |
| --- | --- | --- |
| `list_servers` | — | `servers.json` içeriğini döndürür |
| `run_remote_command` | `server_name`, `command` | Sunucuda komutu çalıştırır; kullanıcıyı, exit kodunu, stdout ve stderr'i döndürür |

## Bir MCP istemcisine bağlama

SSE uç noktası: `https://<alan-adınız>/sse`

Token iki şekilde gönderilebilir:

- Query parametresi: `https://<alan-adınız>/sse?token=<MCP_API_KEY>`
- Başlık: `Authorization: Bearer <MCP_API_KEY>`

**claude.ai:** *Settings → Connectors → Add custom connector* bölümüne query parametreli URL'yi girin.

**Claude Code:**

```bash
claude mcp add --transport sse rhel-gateway https://<alan-adınız>/sse \
  --header "Authorization: Bearer <MCP_API_KEY>"
```

## Geliştirme ve testler

```bash
cd public-gateway
pip install -r requirements-dev.txt
python -m pytest
```

Testler SSH bağlantısını taklit eder ve gerçek `~/.ssh` klasörüne dokunmaz. Uçtan uca testler gerçek bir uvicorn sunucusu ile resmi MCP SSE istemcisini kullanır. GitHub Actions her push ve PR'da testleri Python 3.11 ile çalıştırır.

> `mcp` paketi `<2` sürümüne sabitlenmiştir. Kod, mcp 1.x'teki `Server.list_tools()` / `call_tool()` API'sini kullanır.

## Güvenlik notları

- `MCP_API_KEY` mutlaka tanımlanmalı; gateway, kayıtlı sunucularda root dahil komut çalıştırabilir.
- SSH bağlantılarında sunucu anahtarı doğrulanmıyor (`known_hosts=None`), bu da ortadaki adam (MITM) saldırısına açık bırakır.
- `list_servers` çıktısı key dosyalarının yollarını içerir (key içeriğini değil).

## Lisans

[GNU GPL v3](LICENSE)
