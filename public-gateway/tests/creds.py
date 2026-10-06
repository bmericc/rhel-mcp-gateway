"""Testlerde kullanılan şifreler her çalıştırmada rastgele üretilir (kodda sabit şifre tutulmaz)."""
import secrets

PASSWORD = secrets.token_urlsafe(16)
WRONG_PASSWORD = secrets.token_urlsafe(16)
