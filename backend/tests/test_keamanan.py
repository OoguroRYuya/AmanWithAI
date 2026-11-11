"""
Uji regresi keamanan: setiap celah yang pernah terbukti (injeksi perintah
router, CSRF, pembajakan WebSocket, endpoint tanpa autentikasi) harus
tertutup, dan perilaku sah tetap jalan.
"""

import numpy as np
import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

import keamanan as km
import keputusan as kp
import pipeline
from conftest import PASSWORD_UJI, bingkai, flow
from mitigasi import ModulMitigasi

JAHAT = {"Origin": "http://situs-jahat.example"}
KORBAN = "192.168.30.10"

IP_BERBAHAYA = [
    "203.0.113.5\ndelete firewall group address-group BLOKIR_NDR",  # injeksi perintah
    "0.0.0.0-255.255.255.255",  # rentang seluruh alamat
    "10.0.0.0/8",
    "bukan-ip",
    "192.168.020.5",  # nol di depan
    "0.0.0.0",
    "127.0.0.1",
    "255.255.255.255",
]


@pytest.fixture
def tamu():
    """Klien tanpa sesi admin dan tanpa lifespan (tidak menyentuh router)."""
    return TestClient(__import__("main").app)


def terblokir(klien):
    return {d["ip"] for d in klien.get("/api/terblokir").json()["data"]}


# ------------------------------------------------- injeksi & validasi input


@pytest.mark.parametrize("ip", IP_BERBAHAYA)
def test_ip_berbahaya_ditolak_sebelum_ke_router(klien, ip):
    sebelum = terblokir(klien)
    assert klien.post("/api/mitigasi/blokir", json={"ip": ip}).status_code == 422
    assert klien.post("/api/mitigasi/cabut", json={"ip": ip}).status_code == 422
    assert terblokir(klien) == sebelum


@pytest.mark.parametrize("durasi", [-5, 0, 1441, 10**9])
def test_durasi_di_luar_batas_ditolak(klien, durasi):
    r = klien.post("/api/mitigasi/blokir", json={"ip": "203.0.113.40", "durasi_menit": durasi})
    assert r.status_code == 422


def test_durasi_setujui_di_luar_batas_ditolak(klien):
    assert klien.post("/api/mitigasi/setujui/1", params={"durasi_menit": 0}).status_code == 422


def test_ip_sah_dinormalisasi(klien):
    r = klien.post("/api/mitigasi/blokir", json={"ip": " 203.0.113.41 ", "durasi_menit": 1})
    assert r.status_code == 200 and r.json()["ip"] == "203.0.113.41"


# ------------------------------------------------------- autentikasi admin


@pytest.mark.parametrize("metode,path", [
    ("get", "/api/status"), ("get", "/api/riwayat"), ("get", "/api/terblokir"),
    ("get", "/api/persetujuan"), ("get", "/api/trafik"), ("get", "/api/ringkasan"),
    ("post", "/api/setup-firewall"), ("post", "/api/mitigasi/tolak/1"),
    ("post", "/api/mitigasi/setujui/1"),
])
def test_rute_admin_tanpa_sesi_401(tamu, metode, path):
    assert getattr(tamu, metode)(path).status_code == 401


def test_blokir_tanpa_sesi_401(tamu):
    r = tamu.post("/api/mitigasi/blokir", json={"ip": "203.0.113.42"})
    assert r.status_code == 401


def test_sesi_publik_hanya_status_masuk(tamu):
    assert tamu.get("/api/sesi").json() == {"masuk": False, "dikonfigurasi": True}


def test_password_salah_lalu_dikunci(tamu, monkeypatch):
    import main
    monkeypatch.setattr(main, "pembatas_masuk", km.PembatasMasuk(maks_gagal=2, kunci_detik=60))
    assert tamu.post("/api/masuk", json={"password": "salah"}).status_code == 401
    assert tamu.post("/api/masuk", json={"password": "salah"}).status_code == 401
    # terkunci: password benar pun ditolak sampai jeda habis
    assert tamu.post("/api/masuk", json={"password": PASSWORD_UJI}).status_code == 429


def test_cookie_sesi_httponly_samesite_strict(tamu):
    r = tamu.post("/api/masuk", json={"password": PASSWORD_UJI})
    assert r.status_code == 200
    cookie = r.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=strict" in cookie
    assert tamu.get("/api/status").status_code == 200
    assert tamu.post("/api/keluar").status_code == 200
    assert tamu.get("/api/status").status_code == 401


def test_admin_dari_sumber_lain_403(klien, monkeypatch):
    import konfigurasi as cfg
    monkeypatch.setattr(cfg, "ADMIN_SUMBER", ["127.0.0.1"])
    assert klien.get("/api/status").status_code == 403


# ------------------------------------------------------------------- CSRF


@pytest.mark.parametrize("path", [
    "/api/setup-firewall", "/api/mitigasi/tolak/1", "/api/mitigasi/setujui/1",
])
def test_csrf_origin_asing_403_meski_bersesi(klien, path):
    assert klien.post(path, headers=JAHAT).status_code == 403


def test_csrf_blokir_origin_asing_403(klien):
    r = klien.post("/api/mitigasi/blokir", json={"ip": "203.0.113.43"}, headers=JAHAT)
    assert r.status_code == 403


def test_csrf_masuk_origin_asing_403(tamu):
    assert tamu.post("/api/masuk", json={"password": PASSWORD_UJI}, headers=JAHAT).status_code == 403


# ------------------------------------------------------- kanal mesin ingest


CSV = b"ts,td,pr,sa,sp,da,dp,flg,pkt,byt\n"


def test_ingest_tanpa_token_401(klien):
    r = klien.post("/api/ingest", content=CSV,
                   headers={"Authorization": "", "Content-Type": "text/csv"})
    assert r.status_code == 401


def test_ingest_token_salah_401(klien):
    r = klien.post("/api/ingest", content=CSV,
                   headers={"Authorization": "Bearer salah", "Content-Type": "text/csv"})
    assert r.status_code == 401


def test_ingest_text_plain_ditolak_415(klien):
    # text/plain = "simple request" yang bisa dikirim situs lain tanpa preflight
    r = klien.post("/api/ingest", content=CSV, headers={"Content-Type": "text/plain"})
    assert r.status_code == 415


def test_ingest_terlalu_besar_413(klien, monkeypatch):
    import konfigurasi as cfg
    monkeypatch.setattr(cfg, "INGEST_MAKS_MB", 0)
    r = klien.post("/api/ingest", content=CSV, headers={"Content-Type": "text/csv"})
    assert r.status_code == 413


def test_sesi_admin_bukan_token_ingest(tamu):
    # cookie admin tidak membuka kanal mesin, dan sebaliknya
    tamu.post("/api/masuk", json={"password": PASSWORD_UJI})
    r = tamu.post("/api/ingest", content=CSV, headers={"Content-Type": "text/csv"})
    assert r.status_code == 401


# --------------------------------------------------------------- WebSocket


def test_ws_origin_asing_ditolak(klien):
    with pytest.raises(WebSocketDisconnect):
        with klien.websocket_connect("/ws", headers=JAHAT) as ws:
            ws.receive_json()


def test_ws_tanpa_sesi_ditolak(tamu):
    with pytest.raises(WebSocketDisconnect):
        with tamu.websocket_connect("/ws") as ws:
            ws.receive_json()


# ----------------------------------------------------- /api/deteksi tanpa blokir


class ModelYakinSerangan:
    classes_ = np.array(["ddos_flood", "normal", "port_scanning"])

    def predict(self, X):
        return np.array(["ddos_flood"] * len(X))

    def predict_proba(self, X):
        return np.array([[0.99, 0.005, 0.005]] * len(X))


def test_deteksi_tidak_pernah_memblokir(klien, monkeypatch):
    import main
    monkeypatch.setattr(main, "model", ModelYakinSerangan())
    ip = "203.0.113.77"
    r = klien.post("/api/deteksi", json={"src_ip": ip, "dst_ip": KORBAN})
    assert r.status_code == 200
    hasil = r.json()
    assert hasil["kelas"] == "ddos_flood" and hasil["confidence"] >= 0.99
    assert hasil["dimitigasi"] is False and hasil["saran"]["mitigasi_otomatis"] is False
    assert ip not in terblokir(klien)


def test_header_keamanan(klien):
    r = klien.get("/api/status")
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["x-frame-options"] == "DENY"
    assert r.headers["cache-control"] == "no-store"


# ------------------------------------------- gerbang: subnet terlindungi


PARAM = dict(min_flow=20, ambang_rasio=0.80, ambang_conf_blokir=0.70, ambang_sedang=0.50,
             allowlist=set(), durasi_blokir=15,
             subnet_terlindung=["192.168.10.0/24", "192.168.30.0/24"])


def putuskan(baris, **ubah):
    return kp.putuskan(pipeline.kelompokkan(bingkai(baris))[0], **{**PARAM, **ubah})


def test_ip_klien_dipalsukan_tidak_diblokir_otomatis():
    # flood dengan sumber palsu = IP klien sah yang sedang diam (rasio 1.0)
    klien_sah = "192.168.10.12"
    baris = [flow(klien_sah, KORBAN, "ddos_flood", confidence=0.99) for _ in range(30)]
    [k] = putuskan(baris).keputusan
    assert k.status == kp.MENUNGGU_PERSETUJUAN
    assert k.ip_blokir == [] and k.ip_kandidat == [klien_sah]
    assert k.evaluasi_sumber[0].alasan == kp.ALASAN_TERLINDUNG


def test_subnet_terlindungi_dan_penyerang_dalam_satu_insiden():
    baris = [flow(f"192.168.20.{i}", KORBAN, "ddos_flood", confidence=0.99) for i in range(50, 75)]
    baris += [flow("192.168.10.12", KORBAN, "ddos_flood", confidence=0.99) for _ in range(5)]
    [k] = putuskan(baris).keputusan
    assert k.status == kp.BLOKIR_OTOMATIS
    assert "192.168.10.12" not in k.ip_blokir and len(k.ip_blokir) == 25


def test_tanpa_subnet_terlindungi_perilaku_lama():
    baris = [flow("192.168.10.12", KORBAN, "ddos_flood", confidence=0.99) for _ in range(30)]
    [k] = putuskan(baris, subnet_terlindung=[]).keputusan
    assert k.status == kp.BLOKIR_OTOMATIS


def test_sumber_bukan_ip_tidak_pernah_lolos():
    racun = "1.2.3.4\ndelete firewall"
    baris = [flow(racun, KORBAN, "ddos_flood", confidence=0.99) for _ in range(30)]
    [k] = putuskan(baris).keputusan
    assert k.status == kp.DICATAT and k.ip_blokir == [] and k.ip_kandidat == []


# ------------------------------------------------------- pemutus darurat


def test_pemutus_darurat_mengalihkan_ke_persetujuan():
    baris = [flow(f"192.168.20.{i}", KORBAN, "ddos_flood", confidence=0.99) for i in range(50, 80)]
    hasil = putuskan(baris)
    assert kp.pemutus_darurat(hasil, set(), batas=10) == 30
    [k] = hasil.keputusan
    assert k.status == kp.MENUNGGU_PERSETUJUAN and k.ip_blokir == [] and len(k.ip_kandidat) == 30
    assert "pemutus darurat" in k.alasan and k.saran["mitigasi_otomatis"] is False
    assert hasil.ip_blokir == []


def test_pemutus_darurat_menghitung_hanya_ip_baru():
    ips = {f"192.168.20.{i}" for i in range(50, 80)}
    baris = [flow(ip, KORBAN, "ddos_flood", confidence=0.99) for ip in sorted(ips)]
    hasil = putuskan(baris)
    # 25 dari 30 sudah terblokir: hanya 5 baru, di bawah batas
    sudah = set(sorted(ips)[:25])
    assert kp.pemutus_darurat(hasil, sudah, batas=10) == 0
    assert hasil.keputusan[0].status == kp.BLOKIR_OTOMATIS


# ------------------------------------- modul mitigasi (lapis terdalam)


def test_mitigasi_membuang_ip_berbahaya_dari_batch(tmp_path):
    m = ModulMitigasi("192.0.2.1", "u", "p", dry_run=True)
    hasil = m.blokir_banyak(["192.168.20.10", *IP_BERBAHAYA], durasi_menit=5)
    assert hasil == ["192.168.20.10"]
    assert m.blokir(IP_BERBAHAYA[0]) is False
    assert m.blokir("192.168.20.11", durasi_menit=0) is False
    assert set(m.terblokir) == {"192.168.20.10"}


def test_status_blokir_bertahan_setelah_restart(tmp_path):
    berkas = tmp_path / "terblokir.json"
    m = ModulMitigasi("192.0.2.1", "u", "p", dry_run=True, berkas_status=berkas)
    m.blokir_banyak(["192.168.20.10", "192.168.20.11"], durasi_menit=5)
    m.cabut("192.168.20.11")

    baru = ModulMitigasi("192.0.2.1", "u", "p", dry_run=True, berkas_status=berkas)
    assert set(baru.terblokir) == {"192.168.20.10"}
    assert baru.terblokir["192.168.20.10"] == m.terblokir["192.168.20.10"]


# --------------------------------------------------------- keamanan.py


def test_hash_password():
    h = km.buat_hash("rahasia-panjang-sekali")
    assert km.cocok_password("rahasia-panjang-sekali", h)
    assert not km.cocok_password("salah", h)
    assert not km.cocok_password("apa saja", "")
    assert not km.cocok_password("apa saja", "bukan$hash")


def baca_audit():
    import json
    import konfigurasi as cfg
    if not cfg.BERKAS_AUDIT.exists():
        return []
    return [json.loads(b) for b in cfg.BERKAS_AUDIT.read_text(encoding="utf-8").splitlines()]


def test_audit_mencatat_aksi_admin(klien):
    ip = "203.0.113.90"
    assert klien.post("/api/mitigasi/blokir", json={"ip": ip, "durasi_menit": 3}).status_code == 200
    assert klien.post("/api/mitigasi/cabut", json={"ip": ip}).status_code == 200
    aksi = [(e["aksi"], e["oleh"]) for e in baca_audit() if ip in e.get("ip", [])]
    assert aksi[-2:] == [("blokir", "admin"), ("cabut", "admin")]
    blokir = [e for e in baca_audit() if e["aksi"] == "blokir" and ip in e.get("ip", [])][-1]
    assert blokir["durasi_menit"] == 3 and blokir["berhasil"] is True and blokir["dry_run"] is True


def test_audit_mencatat_akses_ditolak(klien):
    klien.post("/api/setup-firewall", headers=JAHAT)
    terakhir = [e for e in baca_audit() if e["aksi"] == "akses_ditolak"][-1]
    assert terakhir["origin"] == JAHAT["Origin"] and terakhir["path"] == "/api/setup-firewall"


def test_audit_mencatat_login(tamu):
    tamu.post("/api/masuk", json={"password": "salah"})
    assert baca_audit()[-1]["aksi"] == "masuk_gagal"


class NetmikoPalsu:
    def __init__(self):
        self.kwargs = None

    def ConnectHandler(self, **kwargs):  # noqa: N802 (nama API Netmiko)
        self.kwargs = kwargs
        return object()


@pytest.mark.parametrize("key_file,harapan", [
    ("C:/kunci/ndr_vyos", {"use_keys": True, "key_file": "C:/kunci/ndr_vyos", "allow_agent": False}),
    (None, {"password": "rahasia"}),
])
def test_login_router_kunci_ssh_atau_password(monkeypatch, key_file, harapan):
    import sys
    palsu = NetmikoPalsu()
    monkeypatch.setitem(sys.modules, "netmiko", palsu)
    m = ModulMitigasi("192.0.2.1", "ndr", "rahasia", dry_run=False, key_file=key_file)
    m._koneksi()
    for k, v in harapan.items():
        assert palsu.kwargs[k] == v
    if key_file:
        assert "password" not in palsu.kwargs


def test_sumber_diizinkan():
    daftar = ["127.0.0.1", "192.168.172.0/24"]
    assert km.sumber_diizinkan("127.0.0.1", daftar)
    assert km.sumber_diizinkan("192.168.172.128", daftar)
    assert not km.sumber_diizinkan("10.92.68.40", daftar)
    assert not km.sumber_diizinkan(None, daftar)
    assert not km.cocok_token("", "")
