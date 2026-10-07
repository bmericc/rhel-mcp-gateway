"""Interface language: English by default, Turkish as the second language.

Source strings are English and double as translation keys (gettext style). The language of the
current request is picked from the browser's Accept-Language header by `LanguageMiddleware`
and kept in a context variable, so `t()` works anywhere below the request (pages, error
messages, MCP tool descriptions and tool output).
"""
from contextvars import ContextVar

DEFAULT_LANGUAGE = "en"
SUPPORTED_LANGUAGES = ("en", "tr")

_language: ContextVar[str] = ContextVar("language", default=DEFAULT_LANGUAGE)


def get_language() -> str:
    return _language.get()


def set_language(language: str):
    """Returns a token for `reset_language`."""
    return _language.set(language if language in SUPPORTED_LANGUAGES else DEFAULT_LANGUAGE)


def reset_language(token) -> None:
    _language.reset(token)


def pick_language(accept_language: str | None) -> str:
    """Best supported language of an Accept-Language header ("tr-TR,tr;q=0.9,en;q=0.8")."""
    choices = []
    for position, item in enumerate((accept_language or "").split(",")):
        tag, _, params = item.strip().partition(";")
        quality = 1.0
        for param in params.split(";"):
            name, _, value = param.strip().partition("=")
            if name == "q":
                try:
                    quality = float(value)
                except ValueError:
                    quality = 0.0
        primary = tag.strip().lower().split("-")[0]
        if primary in SUPPORTED_LANGUAGES and quality > 0:
            choices.append((-quality, position, primary))
    return min(choices)[2] if choices else DEFAULT_LANGUAGE


def N(message: str) -> str:
    """Marks a string for translation without translating it (module-level constants).

    Pass the constant through `t()` where it is shown.
    """
    return message


def t(message: str, /, **params) -> str:
    """Translates `message` into the current language and fills `{placeholders}`."""
    if _language.get() == "tr":
        message = TR.get(message, message)
    return message.format(**params) if params else message


class LanguageMiddleware:
    """Sets the language of each request from its Accept-Language header."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] in ("http", "websocket"):
            header = dict(scope.get("headers") or []).get(b"accept-language", b"")
            set_language(pick_language(header.decode("latin-1")))
        await self.app(scope, receive, send)


TR = {
    # --- Connections, proxy, SSH ---
    "The server's proxy setting could not be decrypted (SECRET_KEY may have changed); re-enter it in the panel.":
        "Sunucunun proxy ayarı çözülemedi (SECRET_KEY değişmiş olabilir); panelden yeniden girin.",
    "proxy setting unreadable": "proxy ayarı çözülemedi",
    "direct": "doğrudan",
    "proxy {proxy} (default)": "proxy {proxy} (varsayılan)",
    "The key is too large.": "Anahtar çok büyük.",
    "Wrong key passphrase.": "Anahtarın parolası hatalı.",
    "This key is passphrase-protected; enter the key passphrase too.":
        "Bu anahtar parolalı; anahtar parolasını da girin.",
    "Not a valid SSH private key (paste the private key, not the public key).":
        "Geçerli bir SSH özel anahtarı değil (açık anahtar değil, özel anahtar yapıştırın).",
    "Error: no usable SSH key found for '{name}'.": "Hata: '{name}' için kullanılabilir SSH key bulunamadı.",
    "SSH connection error: {reason}": "SSH Bağlantı Hatası: {reason}",
    "connection timed out": "bağlantı zaman aşımına uğradı",
    "SSH authentication failed, users tried:": "SSH Kimlik Doğrulama Hatası, denenen kullanıcılar:",
    "Command timed out after {timeout} seconds.": "Komut {timeout} saniyede zaman aşımına uğradı.",
    "The Cockpit password could not be decrypted (no password was entered, or SECRET_KEY may have changed).":
        "Cockpit şifresi çözülemedi (şifre girilmemiş ya da SECRET_KEY değişmiş olabilir).",
    "{error}; also failed over the SSH tunnel: {reason}": "{error}; SSH tüneli üzerinden de olmadı: {reason}",
    "{error}\nSSH fallback also failed: {reason}": "{error}\nSSH yedeği de başarısız: {reason}",

    # --- outbound_proxy ---
    "The proxy address must start with http://, socks5:// or socks5h://.":
        "Proxy adresi http://, socks5:// veya socks5h:// ile başlamalı.",
    "The proxy address needs a host and a port (e.g. socks5://10.0.0.1:1080).":
        "Proxy adresinde host ve port olmalı (örn. socks5://10.0.0.1:1080).",
    "The proxy address may only consist of a scheme, host and port.":
        "Proxy adresi yalnızca şema, host ve porttan oluşmalı.",
    "invalid proxy": "geçersiz proxy",
    "The proxy closed the connection.": "Proxy bağlantıyı kapattı.",
    "The HTTP proxy closed the connection.": "HTTP proxy bağlantıyı kapattı.",
    "The HTTP proxy response is too long.": "HTTP proxy yanıtı çok uzun.",
    "The HTTP proxy refused the connection: {status}": "HTTP proxy bağlantıyı reddetti: {status}",
    "general failure": "genel hata",
    "not allowed by the ruleset": "kurallar izin vermiyor",
    "network unreachable": "ağa ulaşılamıyor",
    "host unreachable": "hosta ulaşılamıyor",
    "connection refused": "bağlantı reddedildi",
    "TTL expired": "TTL aşıldı",
    "command not supported": "komut desteklenmiyor",
    "address type not supported": "adres türü desteklenmiyor",
    "The SOCKS5 proxy did not accept the authentication method.":
        "SOCKS5 proxy kimlik doğrulama yöntemini kabul etmedi.",
    "The SOCKS5 proxy rejected the username/password.": "SOCKS5 proxy kullanıcı adı/parolayı reddetti.",
    "The SOCKS5 proxy could not connect to the target: {reason}": "SOCKS5 proxy hedefe bağlanamadı: {reason}",
    "The SOCKS5 proxy returned an unexpected address type.": "SOCKS5 proxy beklenmeyen adres türü döndü.",
    "Invalid proxy setting: {error}": "Geçersiz proxy ayarı: {error}",
    "The proxy connection timed out ({proxy})": "Proxy bağlantısı zaman aşımına uğradı ({proxy})",
    "Could not connect to the proxy ({proxy}): {reason}": "Proxy'ye bağlanılamadı ({proxy}): {reason}",
    "Request through the proxy failed ({proxy}): {reason}": "Proxy üzerinden istek başarısız ({proxy}): {reason}",

    # --- cockpit_client ---
    "Could not connect to Cockpit ({url}): {reason}": "Cockpit'e bağlanılamadı ({url}): {reason}",
    "Cockpit login rejected ({user}@{url})": "Cockpit girişi reddedildi ({user}@{url})",
    "Cockpit login failed ({url}): HTTP {status}": "Cockpit girişi başarısız ({url}): HTTP {status}",
    "Could not connect to Cockpit through the proxy ({url}): {reason}":
        "Cockpit'e proxy üzerinden bağlanılamadı ({url}): {reason}",
    "Could not open the Cockpit WebSocket connection ({url}): {reason}":
        "Cockpit WebSocket bağlantısı kurulamadı ({url}): {reason}",
    "Cockpit sent an unexpected first message: {payload}": "Cockpit beklenmeyen ilk mesaj gönderdi: {payload}",
    "Could not open the Cockpit session: {problem}": "Cockpit oturumu açılamadı: {problem}",
    "connection closed": "bağlantı kapandı",
    "Cockpit connection is closed: {reason}": "Cockpit bağlantısı kapalı: {reason}",
    "Cockpit connection lost: {message}": "Cockpit bağlantısı koptu: {message}",
    "Terminated by signal: {signal}": "Sinyal ile sonlandı: {signal}",
    "command not found": "komut bulunamadı",
    "access denied": "yetki reddedildi",
    "could not obtain administrator privileges (the user needs sudo rights)":
        "yönetici yetkisi alınamadı (kullanıcının sudo yetkisi olmalı)",
    "Cockpit error: {problem}": "Cockpit hatası: {problem}",
    "timed out (the port may be closed or blocked by a firewall)":
        "zaman aşımı (port kapalı veya güvenlik duvarı engelliyor olabilir)",

    # --- auth ---
    "Username and password are required.": "Kullanıcı adı ve şifre gerekli.",
    "Wrong username or password.": "Kullanıcı adı veya şifre hatalı.",
    "Could not reach Cockpit; the login could not be verified.": "Cockpit'e ulaşılamadı, giriş doğrulanamadı.",
    "This user is not allowed to access the gateway.": "Bu kullanıcının gateway'e erişim yetkisi yok.",

    # --- MCP tools (main) ---
    "Registered server name (e.g. prod-db)": "Kayıtlı sunucu adı (örn: prod-db)",
    "Lists all registered RHEL servers (without passwords) and whether a Cockpit login is configured.":
        "Kayıtlı tüm RHEL sunucularını (şifreler hariç) ve Cockpit girişi tanımlı olup olmadığını listeler.",
    "Collects a load, failed-service and root-disk-usage summary from all registered servers in parallel.":
        "Tüm kayıtlı sunucuların yük, çökmüş servis ve kök disk doluluğu özetini paralel olarak toplar.",
    "Runs an arbitrary Linux command on a registered server. Prefer a purpose-built tool when one exists. "
    "Runs through Cockpit if the server has a Cockpit login configured; otherwise, or if Cockpit is unreachable, over SSH.":
        "Kayıtlı bir sunucuda serbest bir Linux komutu çalıştırır. Amaca özel bir araç varsa onu tercih edin. "
        "Sunucuya Cockpit girişi tanımlıysa Cockpit üzerinden, değilse veya Cockpit'e ulaşılamazsa SSH ile çalışır.",
    "Linux command to run (e.g. systemctl status nginx)": "Çalıştırılacak Linux komutu (örn: systemctl status nginx)",
    "Run with administrator privileges (Cockpit superuser / sudo -n over SSH)":
        "Yönetici yetkisiyle çalıştır (Cockpit superuser / SSH'ta sudo -n)",
    "Set to true to actually run the command. Otherwise only what would be run is shown.":
        "Komutu gerçekten çalıştırmak için true. Verilmezse sadece ne çalıştırılacağı gösterilir.",
    "Confirmation required: the following will be done on '{server}':\n  {action}\n"
    "Call the same tool again with confirm: true to apply.":
        "Onay gerekli: '{server}' üzerinde şu işlem yapılacak:\n  {action}\n"
        "Uygulamak için aynı aracı confirm: true ile tekrar çağırın.",
    "Unknown tool: {name}": "Bilinmeyen araç: {name}",
    "Error: server '{name}' not found.": "Hata: '{name}' sunucusu hafızada bulunamadı.",
    "Note: Cockpit was unavailable, ran over SSH ({error})": "Not: Cockpit kullanılamadı, SSH ile çalıştırıldı ({error})",

    # --- MCP tools (fleet_tools) ---
    "Invalid {label}: {value}": "Geçersiz {label}: {value}",
    "service name": "servis adı",
    "package name": "paket adı",
    "port (e.g. 8080/tcp)": "port (örn. 8080/tcp)",
    "time expression": "zaman ifadesi",
    "firewalld service name": "firewalld servis adı",
    "At least one package name is required.": "En az bir paket adı verilmeli.",
    "Invalid port: {value}": "Geçersiz port: {value}",
    "Expected a number: {value}": "Sayı bekleniyordu: {value}",
    "... [output truncated, {total} characters total]": "... [çıktı kırpıldı, toplam {total} karakter]",
    "Invalid priority: {value}": "Geçersiz öncelik: {value}",
    "The grep expression may be at most 200 characters.": "grep ifadesi en fazla 200 karakter olabilir.",
    "Invalid sort order: {value}": "Geçersiz sıralama: {value}",
    "No SELinux denials in the last 10 minutes.": "Son 10 dakikada SELinux engellemesi yok.",
    "Invalid action: {value}": "Geçersiz işlem: {value}",
    "Exactly one of the port or service parameters must be given.":
        "port veya service parametrelerinden yalnızca biri verilmeli.",
    "Reboot command sent; the connection is expected to drop.":
        "Yeniden başlatma komutu gönderildi; bağlantının kopması beklenir.",
    "Registered server name": "Kayıtlı sunucu adı",
    "Set to true to actually apply the change. Otherwise only what would be done is shown.":
        "İşlemi gerçekten uygulamak için true. Verilmezse sadece ne yapılacağı gösterilir.",
    "Returns the server's hostname, operating system version, kernel and uptime.":
        "Sunucunun hostname, işletim sistemi sürümü, kernel ve uptime bilgisini döndürür.",
    "Returns memory, swap, system load, CPU count and disk usage.":
        "Bellek, swap, sistem yükü, CPU sayısı ve disk doluluk oranlarını döndürür.",
    "Returns the active/enabled state of a systemd service and its latest log lines.":
        "Bir systemd servisinin aktif/etkin durumunu ve son log satırlarını döndürür.",
    "Service name (e.g. nginx, httpd.service)": "Servis adı (örn. nginx, httpd.service)",
    "Lists failed systemd units.": "Çökmüş (failed) systemd unit'lerini listeler.",
    "Reads filtered logs with journalctl.": "journalctl ile filtreli log okur.",
    "Only logs of this service": "Sadece bu servisin logları",
    "Start time (e.g. '1 hour ago', 'today', '2026-10-06 10:00')":
        "Başlangıç zamanı (örn. '1 hour ago', 'today', '2026-10-06 10:00')",
    "This priority and more severe ones": "Bu öncelik ve daha ciddi olanlar",
    "Expression to search for in the message (regex)": "Mesajda aranacak ifade (regex)",
    "Maximum number of lines (default 100, max 1000)": "En fazla satır sayısı (varsayılan 100, en çok 1000)",
    "Lists the processes using the most CPU or memory.": "En çok CPU veya bellek kullanan süreçleri listeler.",
    "Sort criterion (default cpu)": "Sıralama ölçütü (varsayılan cpu)",
    "Number of processes (default 10, max 50)": "Süreç sayısı (varsayılan 10, en çok 50)",
    "Returns IP addresses, the routing table and listening ports.":
        "IP adreslerini, yönlendirme tablosunu ve dinlenen portları döndürür.",
    "Returns the firewalld state and active rules.": "firewalld durumunu ve aktif kuralları döndürür.",
    "Returns the SELinux mode and recent SELinux (AVC) denials.":
        "SELinux modunu ve son SELinux (AVC) engellemelerini döndürür.",
    "Lists pending package updates.": "Bekleyen paket güncellemelerini listeler.",
    "Security updates only": "Sadece güvenlik güncellemeleri",
    "Returns whether a package is installed, its version and its dnf info.":
        "Bir paketin kurulu olup olmadığını, sürümünü ve dnf bilgisini döndürür.",
    "Package name": "Paket adı",
    "Starts, stops, restarts, reloads, enables or disables a systemd service.":
        "Bir systemd servisini başlatır, durdurur, yeniden başlatır, yeniden yükler, etkinleştirir veya devre dışı bırakır.",
    "Service name": "Servis adı",
    "Installs package updates with dnf.": "dnf ile paket güncellemelerini kurar.",
    "Installs packages with dnf.": "dnf ile paket kurar.",
    "Package names": "Paket adları",
    "Removes packages with dnf.": "dnf ile paket kaldırır.",
    "Adds/removes a permanent firewalld port or service rule and reloads.":
        "firewalld'ye kalıcı port veya servis kuralı ekler/kaldırır ve yeniden yükler.",
    "Port/protocol (e.g. 8080/tcp, 3000-3010/udp)": "Port/protokol (örn. 8080/tcp, 3000-3010/udp)",
    "firewalld service name (e.g. http, https)": "firewalld servis adı (örn. http, https)",
    "Reboots the server.": "Sunucuyu yeniden başlatır.",

    # --- Panel: layout ---
    "Servers": "Sunucular",
    "SSH Keys": "SSH Anahtarları",
    "Audit Log": "İşlem Kayıtları",
    "Menu": "Menü",
    "Log out": "Çıkış Yap",
    "Access denied": "Yetkiniz yok",
    "Log in": "Giriş yap",
    "Invalid login request": "Giriş isteği geçersiz",
    "The login request is invalid or has expired. Connect again from the MCP client.":
        "Giriş isteği geçersiz veya süresi dolmuş. MCP istemcisinden tekrar bağlanın.",

    # --- Panel: public IP ---
    "could not be determined": "belirlenemedi",
    "Default proxy ({proxy}) egress IP address:": "Varsayılan proxy ({proxy}) çıkış IP adresi:",
    "Servers that use the proxy see this address; allow this address on them.":
        "Proxy kullanan sunucular bu adresi görür; onlarda bu adrese izin verin.",
    "The gateway's public IP address could not be determined (outbound access may be blocked).":
        "Gateway'in dış IP adresi belirlenemedi (dışarıya erişim kapalı olabilir).",
    "Example (RHEL, firewalld):": "Örnek (RHEL, firewalld):",
    "Gateway public IP address:": "Gateway dış IP adresi:",
    "Refresh": "Yenile",
    "On remote servers, allow this address for Cockpit (9090/tcp) and 22/tcp for the SSH fallback. "
    "Servers on the same local network see the local IP address of the machine running the gateway instead.":
        "Uzaktaki sunucularda bu adrese Cockpit (9090/tcp) ve SSH yedeği için 22/tcp izni verin. "
        "Aynı yerel ağdaki sunucular ise gateway'i çalıştıran makinenin yerel IP adresini görür.",
    "Public IP address: {ips}": "Dış IP adresi: {ips}",
    "The public IP address could not be determined.": "Dış IP adresi belirlenemedi.",

    # --- Panel: connection check ---
    "Could not run a command through Cockpit: {reason}": "Cockpit üzerinden komut çalıştırılamadı: {reason}",
    "SSH command failed: {reason}": "SSH komutu başarısız: {reason}",
    "The Cockpit password could not be decrypted; re-enter the password.":
        "Cockpit şifresi çözülemedi; şifreyi yeniden girin.",
    "Cockpit connection successful.": "Cockpit bağlantısı başarılı.",
    "Connected to Cockpit over the SSH tunnel (the Cockpit port is not reachable from outside).":
        "Cockpit SSH tüneli üzerinden bağlandı (Cockpit portu dışarıya kapalı).",
    "Cockpit over the SSH tunnel: {error}": "SSH tüneliyle Cockpit: {error}",
    "Connected with the SSH fallback; Cockpit is not working: {error}.":
        "SSH yedeği ile bağlanıldı; Cockpit çalışmıyor: {error}.",
    "{error} (the SSH fallback is not working either: {ssh_error})":
        "{error} (SSH yedeği de çalışmıyor: {ssh_error})",
    "SSH connection successful.": "SSH bağlantısı başarılı.",

    # --- Panel: servers ---
    "automatic": "otomatik",
    "Not tested": "Test edilmedi",
    "Test": "Test et",
    "Delete": "Sil",
    "Delete {name}?": "{name} silinsin mi?",
    "No servers defined yet.": "Henüz tanımlı sunucu yok.",
    "No shared keys yet.": "Henüz ortak anahtar yok.",
    "Welcome, {user}!": "Hoş geldiniz, {user}!",
    "MCP Gateway is active. SSE endpoint:": "MCP Gateway aktif. SSE Uç Noktası:",
    "Registered Servers": "Kayıtlı Sunucular",
    "Name": "Ad",
    "SSH (fallback)": "SSH (yedek)",
    "Connection status": "Bağlantı durumu",
    "Add / Update Server": "Sunucu Ekle / Güncelle",
    "Saving with an existing name updates that server. If the password field is left empty, the current password is kept. "
    "Before saving, the gateway connects to the server to verify the details; if no connection can be made, nothing is saved.":
        "Aynı adla kaydetmek mevcut sunucuyu günceller. Şifre alanı boş bırakılırsa mevcut şifre korunur. "
        "Kaydetmeden önce sunucuya bağlanılıp bilgiler doğrulanır; bağlantı kurulamazsa kayıt yapılmaz.",
    "Server name *": "Sunucu adı *",
    "Host (IP / domain name) *": "Host (IP / alan adı) *",
    "Cockpit user": "Cockpit kullanıcısı",
    "Cockpit password": "Cockpit parolası",
    "Cockpit address": "Cockpit adresi",
    "https://HOST:9090 (if empty)": "https://HOST:9090 (boşsa)",
    "Verify TLS certificate": "TLS sertifikasını doğrula",
    "SSH user": "SSH kullanıcısı",
    "SSH_LOGINS order if empty": "boşsa SSH_LOGINS sırası",
    "SSH port": "SSH portu",
    "SSH key path": "SSH key yolu",
    "the user's .ssh folder if empty": "boşsa kullanıcının .ssh klasörü",
    "Connection proxy": "Bağlantı proxy'si",
    "Cockpit and SSH connections go through this proxy; the server sees the proxy's IP address. "
    "If left empty, the current setting is kept (a new server uses the default).":
        "Cockpit ve SSH bağlantıları bu proxy üzerinden yapılır; sunucu proxy'nin IP adresini görür. "
        "Boş bırakılırsa mevcut ayar korunur (yeni sunucuda varsayılan kullanılır).",
    "the default (OUTBOUND_PROXY in .env{value})": "varsayılan (.env'deki OUTBOUND_PROXY{value})",
    "no proxy.": "proxysiz.",
    "A username/password can be given in the address (socks5://user:password@host:1080) and is stored encrypted.":
        "Kullanıcı adı/parola adreste verilebilir (socks5://kullanici:parola@host:1080) ve şifreli saklanır.",
    "Save without testing the connection": "Bağlantıyı test etmeden kaydet",
    "Save": "Kaydet",
    "The server name may only contain letters, digits, dots, underscores and hyphens.":
        "Sunucu adı yalnızca harf, rakam, nokta, alt çizgi ve tire içerebilir.",
    "Invalid host.": "Geçersiz host.",
    "Invalid SSH port.": "Geçersiz SSH portu.",
    "The Cockpit address must look like https://host:9090.": "Cockpit adresi https://host:9090 biçiminde olmalı.",
    "Invalid proxy: {error}": "Geçersiz proxy: {error}",
    "A password is required for the Cockpit user.": "Cockpit kullanıcısı için şifre gerekli.",
    "Saved without a connection test.": "Bağlantı testi yapılmadan kaydedildi.",
    "'{name}' saved without a connection test.": "'{name}' bağlantı testi yapılmadan kaydedildi.",
    "'{name}' was not saved, could not connect: {message}": "'{name}' kaydedilmedi, bağlantı kurulamadı: {message}",
    "'{name}' saved.": "'{name}' kaydedildi.",
    "'{name}' not found.": "'{name}' bulunamadı.",
    "Server not found.": "Sunucu bulunamadı.",

    # --- Panel: shared SSH keys ---
    "Shared SSH Keys": "Ortak SSH Anahtarları",
    "The keys here are tried on all servers, for every user, in the SSH fallback. "
    "To use one, add the public part of the key to <code>~/.ssh/authorized_keys</code> on the servers. "
    "Private keys are stored encrypted in <code>data/ssh_keys.json</code> and are not shown in the panel.":
        "Buradaki anahtarlar SSH yedeğinde tüm sunucularda, her kullanıcı için denenir. "
        "Kullanmak için anahtarın açık kısmını sunuculardaki <code>~/.ssh/authorized_keys</code> dosyasına ekleyin. "
        "Özel anahtarlar <code>data/ssh_keys.json</code> içinde şifreli saklanır ve panelde gösterilmez.",
    "Type / fingerprint": "Tür / parmak izi",
    "Public key (authorized_keys line)": "Açık anahtar (authorized_keys satırı)",
    "Key name *": "Anahtar adı *",
    "shared-key": "ortak-anahtar",
    "Private key *": "Özel anahtar *",
    "Key passphrase": "Anahtar parolası",
    "empty if none": "parolasızsa boş",
    "Add key": "Anahtarı ekle",
    "Generate a new key": "Yeni anahtar üret",
    "key name": "anahtar adı",
    "Generate Ed25519 key": "Ed25519 anahtarı üret",
    "Delete key {name}?": "{name} anahtarı silinsin mi?",
    "The key name may only contain letters, digits, dots, underscores and hyphens.":
        "Anahtar adı yalnızca harf, rakam, nokta, alt çizgi ve tire içerebilir.",
    "A key named '{name}' already exists. Delete it first to replace it.":
        "'{name}' adında bir anahtar zaten var. Değiştirmek için önce silin.",
    "Key not added: {error}": "Anahtar eklenmedi: {error}",
    "Key '{name}' added ({fingerprint}).": "'{name}' anahtarı eklendi ({fingerprint}).",
    "A key named '{name}' already exists.": "'{name}' adında bir anahtar zaten var.",
    "Key '{name}' generated. Add the public key to the authorized_keys file on the servers.":
        "'{name}' anahtarı üretildi. Açık anahtarı sunuculardaki authorized_keys dosyasına ekleyin.",
    "Key '{name}' deleted.": "'{name}' anahtarı silindi.",

    # --- Panel: audit log ---
    "✗ error": "✗ hata",
    "awaiting confirmation": "onay bekliyor",
    "Parameters": "Parametreler",
    "exit": "çıkış",
    "Commands run": "Çalıştırılan komutlar",
    "Result": "Sonuç",
    "{count} command(s)": "{count} komut",
    "Details": "Ayrıntı",
    "No entries.": "Kayıt yok.",
    "← Newer": "← Daha yeni",
    "Page {page}": "Sayfa {page}",
    "Older →": "Daha eski →",
    "Audit log": "İşlem kayıtları",
    "MCP tool calls, panel actions and logins. The newest entry is on top. "
    "Entries are kept in <code>{file}</code>; passwords and keys are not recorded.":
        "MCP araç çağrıları, panel işlemleri ve girişler. En yeni kayıt üsttedir. "
        "Kayıtlar <code>{file}</code> dosyasında tutulur; şifreler ve anahtarlar kaydedilmez.",
    "Search (command, tool, output…)": "Ara (komut, araç, çıktı…)",
    "User": "Kullanıcı",
    "Server": "Sunucu",
    "All sources": "Tüm kaynaklar",
    "All statuses": "Tüm durumlar",
    "Success": "Başarılı",
    "Error": "Hata",
    "Awaiting confirmation": "Onay bekliyor",
    "Filter": "Filtrele",
    "Clear": "Temizle",
    "Time": "Zaman",
    "Source": "Kaynak",
    "Action": "İşlem",
    "Status": "Durum",

    # --- Login ---
    "Log in with your Cockpit username and password ({url}).":
        "Cockpit kullanıcı adınız ve parolanızla giriş yapın ({url}).",
    "Username": "Kullanıcı adı",
    "Gateway password": "Gateway parolası",
    "Wrong gateway password.": "Gateway parolası hatalı.",
    "RHEL MCP Gateway - Login": "RHEL MCP Gateway - Giriş",
    "Grant Access to MCP Client": "MCP İstemcisine Erişim İzni",
    "<b>{client}</b> wants to access the tools on this gateway.":
        "<b>{client}</b> bu gateway'deki araçlara erişmek istiyor.",
    "Authentication rejected.": "Kimlik doğrulama reddedildi.",
    "Login with a Cockpit account is required": "Cockpit hesabıyla giriş gerekli",
}
