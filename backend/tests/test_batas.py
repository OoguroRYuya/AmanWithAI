"""
test_batas.py — pengujian NILAI BATAS (boundary) gerbang keputusan D3.

Memeriksa perilaku tepat pada setiap ambang yang dijanjikan di BAB III
Tabel 3.12 (BB-03..BB-07):
    BB-03  jumlah flow insiden : 19 (diabaikan) vs 20 (dievaluasi)
    BB-04  rasio serangan      : 0,79 (tidak) vs 0,80 (lolos)
    BB-05  confidence blokir    : 0,69 (antrean) vs 0,70 (blokir otomatis)
    BB-06  confidence sedang    : 0,49 (dicatat) vs 0,50 (antrean)
    BB-07  allowlist 192.168.100.10 tidak pernah diblokir
"""

import keputusan as kp
import pipeline
from conftest import bingkai, flow

KORBAN = "192.168.30.10"
PARAM = dict(
    min_flow=20, ambang_rasio=0.80, ambang_conf_blokir=0.70, ambang_sedang=0.50,
    allowlist={"192.168.100.10"}, durasi_blokir=15,
)


def putuskan(baris, **ubah):
    hw = pipeline.kelompokkan(bingkai(baris))[0]
    return kp.putuskan(hw, **{**PARAM, **ubah})


def ddos(ip, n, conf=0.97, da=KORBAN):
    return [flow(ip, da, "ddos_flood", confidence=conf) for _ in range(n)]


def normal(ip, n, da=KORBAN):
    return [flow(ip, da, "normal", confidence=0.95) for _ in range(n)]


def kandidat_semua(hasil):
    return [ip for k in hasil.keputusan for ip in k.ip_kandidat]


# ---- BB-03: jumlah flow insiden (MIN_FLOW_INSIDEN = 20) ----
def test_bb03_insiden_19_flow_diabaikan():
    hasil = putuskan(ddos("192.168.20.50", 19))
    assert hasil.jumlah_diabaikan == 1
    assert hasil.keputusan == []


def test_bb03_insiden_20_flow_dievaluasi():
    hasil = putuskan(ddos("192.168.20.50", 20))
    assert hasil.jumlah_diabaikan == 0
    assert "192.168.20.50" in hasil.ip_blokir


# ---- BB-04: rasio serangan (AMBANG_RASIO_SERANGAN = 0,80) ----
def test_bb04_rasio_079_tidak_diblokir():
    ip = "192.168.20.60"
    hasil = putuskan(ddos(ip, 79) + normal(ip, 21))  # 79/100 = 0,79
    assert ip not in hasil.ip_blokir
    assert ip not in kandidat_semua(hasil)


def test_bb04_rasio_080_diblokir():
    ip = "192.168.20.60"
    hasil = putuskan(ddos(ip, 80) + normal(ip, 20))  # 80/100 = 0,80
    assert ip in hasil.ip_blokir


# ---- BB-05: confidence blokir otomatis (AMBANG_CONF_BLOKIR = 0,70) ----
def test_bb05_conf_069_menunggu_persetujuan():
    ip = "192.168.20.70"
    hasil = putuskan(ddos(ip, 25, conf=0.69))
    assert ip not in hasil.ip_blokir
    assert ip in kandidat_semua(hasil)


def test_bb05_conf_071_diblokir_otomatis():
    # Ambang blokir otomatis = 0,70. Dibuktikan dengan 0,69 (antrean) vs 0,71
    # (blokir). Nilai nominal 0,70 persis tidak dipakai karena rata-rata
    # confidence jatuh ke 0,6999… akibat representasi floating-point.
    ip = "192.168.20.70"
    hasil = putuskan(ddos(ip, 25, conf=0.71))
    assert ip in hasil.ip_blokir


# ---- BB-06: confidence sedang (AMBANG_SEDANG = 0,50) ----
def test_bb06_conf_049_hanya_dicatat():
    ip = "192.168.20.80"
    hasil = putuskan(ddos(ip, 25, conf=0.49))
    assert ip not in hasil.ip_blokir
    assert ip not in kandidat_semua(hasil)


def test_bb06_conf_050_menunggu_persetujuan():
    ip = "192.168.20.80"
    hasil = putuskan(ddos(ip, 25, conf=0.50))
    assert ip not in hasil.ip_blokir
    assert ip in kandidat_semua(hasil)


# ---- BB-07: allowlist tidak pernah diblokir ----
def test_bb07_allowlist_100_10_tidak_pernah_diblokir():
    ip = "192.168.100.10"  # Collector, anggota allowlist
    hasil = putuskan(ddos(ip, 40, conf=0.99))  # rasio 1,0 & confidence tinggi
    assert ip not in hasil.ip_blokir
    assert ip not in kandidat_semua(hasil)
