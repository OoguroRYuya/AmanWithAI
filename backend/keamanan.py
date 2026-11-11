"""
keamanan.py
===========
Autentikasi dan kontrol akses backend (security by design).

Dua kanal dengan kredensial terpisah:
    - admin (dashboard): password -> sesi di memori, dikirim sebagai cookie
      HttpOnly + SameSite=Strict. Setiap permintaan yang mengubah sesuatu
      dan handshake WebSocket juga wajib berasal dari ORIGIN_FRONTEND.
    - mesin (kirim_flow.sh): token Bearer khusus /api/ingest.

Sumber koneksi dibatasi per kanal (ADMIN_SUMBER, INGEST_SUMBER) sebagai
lapis tambahan di atas firewall host.

Membuat nilai .env:
    python keamanan.py            # menanyakan password admin, mencetak
                                  # ADMIN_PASSWORD_HASH dan INGEST_TOKEN
"""

import base64
import hashlib
import hmac
import ipaddress
import json
import logging
import os
import secrets
import time
from datetime import datetime

log = logging.getLogger("ndr.audit")

# Parameter scrypt (n=2^15, r=8, p=1): rekomendasi OWASP untuk password
_N, _R, _P = 2 ** 15, 8, 1
_MAKS_MEM = 64 * 1024 * 1024

NAMA_COOKIE = "ndr_sesi"


# ---------------------------------------------------------------- password


def buat_hash(password):
    garam = secrets.token_bytes(16)
    turunan = hashlib.scrypt(password.encode(), salt=garam, n=_N, r=_R, p=_P,
                             maxmem=_MAKS_MEM, dklen=32)
    b64 = lambda b: base64.b64encode(b).decode()  # noqa: E731
    return f"scrypt${_N}${_R}${_P}${b64(garam)}${b64(turunan)}"


def cocok_password(password, hash_tersimpan):
    """Perbandingan waktu-konstan; hash kosong atau rusak = selalu gagal."""
    try:
        nama, n, r, p, garam, turunan = hash_tersimpan.split("$")
        if nama != "scrypt":
            return False
        dihitung = hashlib.scrypt(password.encode(), salt=base64.b64decode(garam),
                                  n=int(n), r=int(r), p=int(p), maxmem=_MAKS_MEM,
                                  dklen=len(base64.b64decode(turunan)))
        return hmac.compare_digest(dihitung, base64.b64decode(turunan))
    except (ValueError, TypeError):
        return False


def cocok_token(diberikan, seharusnya):
    if not seharusnya or not diberikan:
        return False
    return hmac.compare_digest(diberikan.encode(), seharusnya.encode())


# ---------------------------------------------------------------- sumber


def sumber_diizinkan(host, daftar):
    """True bila host (IP peer) cocok dengan salah satu IP/CIDR di daftar."""
    if host is None:
        return False
    try:
        alamat = ipaddress.ip_address(host)
    except ValueError:
        # nama non-IP (mis. "testclient" milik TestClient) dicocokkan persis
        return host in daftar
    for entri in daftar:
        try:
            if alamat in ipaddress.ip_network(entri, strict=False):
                return True
        except ValueError:
            continue
    return False


def di_subnet(ip, daftar_subnet):
    try:
        alamat = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(alamat in ipaddress.ip_network(s, strict=False) for s in daftar_subnet)


# ------------------------------------------------------------------- sesi


class PenyimpanSesi:
    """Sesi admin di memori: hilang saat restart (admin masuk lagi)."""

    def __init__(self, idle_detik, maks_detik):
        self.idle = idle_detik
        self.maks = maks_detik
        self._sesi = {}  # token -> (dibuat, terakhir_dipakai)

    def buat(self):
        token = secrets.token_urlsafe(32)
        sekarang = time.monotonic()
        self._sesi[token] = (sekarang, sekarang)
        return token

    def valid(self, token):
        if not token or token not in self._sesi:
            return False
        dibuat, terakhir = self._sesi[token]
        sekarang = time.monotonic()
        if sekarang - terakhir > self.idle or sekarang - dibuat > self.maks:
            del self._sesi[token]
            return False
        self._sesi[token] = (dibuat, sekarang)
        return True

    def hapus(self, token):
        self._sesi.pop(token, None)


class PembatasMasuk:
    """Setelah `maks_gagal` percobaan gagal, login dikunci `kunci_detik`."""

    def __init__(self, maks_gagal=5, kunci_detik=60):
        self.maks_gagal = maks_gagal
        self.kunci_detik = kunci_detik
        self._gagal = 0
        self._terkunci_sampai = 0.0

    def sisa_kunci(self):
        return max(0, int(self._terkunci_sampai - time.monotonic()))

    def catat(self, berhasil):
        if berhasil:
            self._gagal = 0
            return
        self._gagal += 1
        if self._gagal >= self.maks_gagal:
            self._gagal = 0
            self._terkunci_sampai = time.monotonic() + self.kunci_detik


# ------------------------------------------------------------------ audit


def catat_audit(berkas, aksi, oleh, **detail):
    """
    Menambah satu baris JSON ke log audit (tambah-saja, bertahan setelah
    restart). Kegagalan menulis dicatat di log aplikasi tetapi tidak pernah
    menggagalkan aksi yang diaudit.
    """
    entri = {"waktu": datetime.now().isoformat(timespec="seconds"), "aksi": aksi, "oleh": oleh, **detail}
    try:
        os.makedirs(os.path.dirname(os.path.abspath(berkas)), exist_ok=True)
        with open(berkas, "a", encoding="utf-8") as f:
            f.write(json.dumps(entri, ensure_ascii=False, default=str) + "\n")
    except OSError as e:
        log.error(f"Log audit {berkas} gagal ditulis: {e} | {entri}")


if __name__ == "__main__":
    import getpass

    pw = getpass.getpass("Password admin baru (min. 12 karakter): ")
    if len(pw) < 12:
        raise SystemExit("Password terlalu pendek.")
    if pw != getpass.getpass("Ulangi: "):
        raise SystemExit("Password tidak sama.")
    print("\nSalin ke backend/.env:\n")
    print(f"ADMIN_PASSWORD_HASH={buat_hash(pw)}")
    print(f"INGEST_TOKEN={secrets.token_urlsafe(32)}")
    print("\nINGEST_TOKEN yang sama dipakai kirim_flow.sh di host VM GNS3.")
