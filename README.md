# RHEL MCP Gateway

[![tests](https://github.com/bmericc/rhel-mcp-gateway/actions/workflows/tests.yml/badge.svg)](https://github.com/bmericc/rhel-mcp-gateway/actions/workflows/tests.yml)

RHEL sunucularını, üzerlerindeki [Cockpit](https://cockpit-project.org) aracılığıyla [Model Context Protocol (MCP)](https://modelcontextprotocol.io) istemcilerine (Claude vb.) açan bir gateway. Yapay zekâ asistanı sunucuların durumunu okuyabilir, servis/paket/firewall yönetebilir ve komut çalıştırabilir.

```
MCP istemcisi ──MCP (SSE + OAuth)──▶ public-gateway (:7435) ──Cockpit (wss://host:9090)──▶ RHEL sunucuları
                                            │                 └─SSH (yedek)───────────────▶
                                            └── giriş: Cockpit hesabı (COCKPIT_AUTH_URL)
```

- Komutlar sunucudaki **Cockpit** üzerinden çalışır. Cockpit'e ulaşılamazsa **SSH** yedek olarak kullanılır.
- Gateway'e giriş (web paneli ve MCP istemcileri) **Cockpit hesabıyla** yapılır. Ayrı bir kullanıcı veritabanı yoktur.

## Kurulum

```bash
cp sample.env .env      # değerleri düzenleyin
docker compose up -d --build
```

Gateway `7435` portunda çalışır. Önüne HTTPS sonlandıran bir reverse proxy (nginx, Caddy vb.) koyun; uygulama `X-Forwarded-*` başlıklarını dikkate alır.

Hedef sunucularda Cockpit açık olmalı:

```bash
sudo dnf install -y cockpit
sudo systemctl enable --now cockpit.socket
sudo firewall-cmd --permanent --add-service=cockpit && sudo firewall-cmd --reload
```

### Ortam değişkenleri (`.env`)

| Değişken | Açıklama |
| --- | --- |
| `SECRET_KEY` | Oturum çerezlerini imzalar, Cockpit şifrelerini şifreler. Uzun ve rastgele olmalı. **Değiştirilirse kayıtlı Cockpit şifreleri çözülemez.** |
| `PORT` | Dinlenecek port (varsayılan `7435`) |
| `PUBLIC_URL` | Gateway'in dışarıdan erişilen adresi, örn. `https://mcp.ornek.com`. OAuth yönlendirmeleri bunu kullanır. |
| `COCKPIT_AUTH_URL` | Girişleri doğrulayacak Cockpit. Varsayılan `https://host.docker.internal:9090` (gateway'in çalıştığı host makine). |
| `COCKPIT_AUTH_VERIFY_TLS` | Bu Cockpit'in sertifikası doğrulansın mı (varsayılan `false`) |
| `ALLOWED_USERS` | Gateway'e girebilecek Cockpit kullanıcıları (virgülle). **Boş bırakılırsa o makinede Cockpit'e girebilen her kullanıcı girebilir.** |
| `MCP_API_KEY` | Opsiyonel sabit token (OAuth desteklemeyen istemciler için). Boşsa devre dışı. |
| `SSH_LOGINS` | SSH yedeğinde denenecek kullanıcılar ve key klasörleri. Varsayılan: `root:/root/.ssh,bmericc:/home/bmericc/.ssh` |

`docker-compose.yml`, host makineye `host.docker.internal` adıyla erişim sağlar. Ayrıca `/root/.ssh` ve `/home/bmericc/.ssh` klasörlerini salt okunur bağlar.

## Giriş ve MCP istemcisine bağlanma

MCP uç noktası: `https://<PUBLIC_URL>/sse`

| Yöntem | Kullanım |
| --- | --- |
| **OAuth 2.1** (önerilen) | İstemci bağlanınca tarayıcıda Cockpit giriş sayfası açılır. Giriş yapılınca istemci token alır (1 saat; refresh token 30 gün). |
| **HTTP Basic** | `Authorization: Basic base64(kullanıcı:şifre)`, Cockpit hesabıyla |
| **Sabit token** | `MCP_API_KEY` tanımlıysa `Authorization: Bearer <token>` veya `?token=<token>` |

**claude.ai:** *Settings → Connectors → Add custom connector* bölümüne `https://<PUBLIC_URL>/sse` adresini girin. Bağlanırken açılan sayfada Cockpit hesabınızla giriş yapın.

**Claude Code:**

```bash
claude mcp add --transport sse rhel-gateway https://<PUBLIC_URL>/sse
```

OAuth akışı uç noktaları:
- `/.well-known/oauth-protected-resource/sse`
- `/.well-known/oauth-authorization-server`
- `/register` (dinamik istemci kaydı)
- `/authorize` (PKCE)
- `/token`
- `/revoke`

Token'lar `data/oauth.json` dosyasında hash'lenmiş olarak saklanır.

## Sunucu ekleme

Web panelinde (`https://<PUBLIC_URL>/`) Cockpit hesabınızla giriş yapın. Ardından *Sunucu Ekle / Güncelle* formunu doldurun:

| Alan | Açıklama |
| --- | --- |
| Sunucu adı, Host | Zorunlu |
| Cockpit kullanıcısı / şifresi | Komutların çalışacağı Cockpit hesabı. Yönetici işlemleri için bu kullanıcının sudo yetkisi olmalı. |
| Cockpit adresi | Boşsa `https://HOST:9090` |
| TLS sertifikasını doğrula | Kendinden imzalı sertifikada kapalı bırakın |
| SSH kullanıcısı / portu / key yolu | Cockpit'e ulaşılamazsa kullanılacak yedek |

Sunucular `data/servers.json` dosyasında tutulur ve bu dosya git'e alınmaz. Cockpit şifreleri dosyada şifrelidir; `list_servers` aracı şifreleri göstermez.

### Bağlantı sırası

1. Sunucuda Cockpit kullanıcısı tanımlıysa önce **Cockpit** denenir. Yönetici işlemleri Cockpit'in superuser (sudo) mekanizmasıyla yapılır.
2. Cockpit'e ulaşılamazsa veya giriş reddedilirse **SSH** kullanılır. Önce sunucuya tanımlı kullanıcı, sonra `SSH_LOGINS` sırası denenir. Root olmayan kullanıcıda yönetici komutları `sudo -n` ile çalışır.

Her araç çıktısında hangi yolla bağlanıldığı yazar: `"connection": {"via": "cockpit"}`.

## MCP araçları

**Okuma araçları** (onay gerekmez):

| Araç | Açıklama |
| --- | --- |
| `list_servers` | Kayıtlı sunucular |
| `fleet_health` | Tüm sunucuların yük, çökmüş servis ve kök disk özeti (paralel) |
| `server_info` | Hostname, OS sürümü, kernel, uptime |
| `resource_usage` | Bellek, swap, yük, CPU, disk doluluğu |
| `service_status` | Servis durumu ve son loglar |
| `failed_services` | Çökmüş systemd unit'leri |
| `read_logs` | `journalctl` (unit, zaman, öncelik, arama filtresi) |
| `top_processes` | En çok CPU/bellek kullanan süreçler |
| `network_info` | IP'ler, rotalar, dinlenen portlar |
| `firewall_status` | firewalld durumu ve kurallar |
| `selinux_status` | SELinux modu ve son engellemeler |
| `available_updates` | Bekleyen (güvenlik) güncellemeleri |
| `package_info` | Paket kurulu mu, sürümü |

**Değiştiren araçlar** (`confirm: true` olmadan yalnızca ne yapılacağını gösterir):

| Araç | Açıklama |
| --- | --- |
| `service_action` | start / stop / restart / reload / enable / disable |
| `install_updates` | `dnf upgrade` (opsiyonel yalnızca güvenlik) |
| `package_install` / `package_remove` | dnf ile paket kur / kaldır |
| `firewall_rule` | Kalıcı port/servis kuralı ekle/kaldır |
| `reboot_server` | Yeniden başlat |
| `run_remote_command` | Serbest komut (`as_root` ile yönetici yetkisi) |

Girdiler (servis, paket, port vb.) doğrulanır. Komutlar argv olarak verildiği için komut enjeksiyonuna kapalıdır. Çıktılar JSON döner, uzun çıktılar kırpılır, komutlar zaman aşımına uğrar.

## Geliştirme ve testler

```bash
cd public-gateway
pip install -r requirements-dev.txt
python -m pytest
```

- Testler gerçek sunuculara bağlanmaz. SSH taklit edilir; Cockpit için `tests/fake_cockpit.py` içinde gerçek cockpit-ws davranışına göre yazılmış bir sahte sunucu kullanılır.
- Gerçek bir Cockpit'e karşı test:

  ```bash
  COCKPIT_TEST_URL=https://host:9090 COCKPIT_TEST_USER=... COCKPIT_TEST_PASSWORD=... python -m pytest tests/test_cockpit_real.py
  ```
- GitHub Actions her push ve PR'da testleri Python 3.11 ile çalıştırır.

> `mcp` paketi `<2` sürümüne sabitlenmiştir; kod mcp 1.x API'sini kullanır.

## Güvenlik notları

- `ALLOWED_USERS`'ı mutlaka doldurun. Gateway, kayıtlı sunucularda yönetici yetkisiyle işlem yapabilir.
- Cockpit bağlantılarında TLS doğrulaması varsayılan olarak kapalıdır (kendinden imzalı sertifikalar için). SSH yedeğinde sunucu anahtarı doğrulanmaz (`known_hosts=None`). İkisi de güvenilir ağ varsayar.
- `SECRET_KEY`'i gizli tutun ve değiştirmeyin.

## Bileşenler

| Klasör | Açıklama |
| --- | --- |
| `public-gateway/` | MCP sunucusu, OAuth yetkilendirme, web paneli, Cockpit ve SSH istemcileri |
| `internal-agent/` | WebSocket ile gateway'e bağlanması planlanan ajan. **Henüz kullanılmıyor.** |

## Lisans

[GNU GPL v3](LICENSE)
