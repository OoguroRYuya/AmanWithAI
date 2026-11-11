"""
test_batas_float.py — uji nilai batas confidence TEPAT di ambang blokir (0,70),
menjawab koreksi Pak Deni butir 50 (galat floating-point + konsistensi gerbang).

Setelah perbaikan keputusan.py (pembanding _memenuhi dengan toleransi, dipakai
sama oleh gerbang blokir dan antrean):
    conf 0,699999  -> menunggu persetujuan (di bawah ambang)
    conf 0,70      -> blokir otomatis      (tepat di ambang)
    conf 0,700001  -> blokir otomatis      (di atas ambang)
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


def ddos(ip, n, conf):
    return [flow(ip, KORBAN, "ddos_flood", confidence=conf) for _ in range(n)]


def kandidat_semua(hasil):
    return [ip for k in hasil.keputusan for ip in k.ip_kandidat]


def test_conf_0699999_menunggu_persetujuan():
    ip = "192.168.20.90"
    hasil = putuskan(ddos(ip, 25, conf=0.699999))
    assert ip not in hasil.ip_blokir
    assert ip in kandidat_semua(hasil)


def test_conf_070_blokir_otomatis():
    ip = "192.168.20.90"
    hasil = putuskan(ddos(ip, 25, conf=0.70))
    assert ip in hasil.ip_blokir


def test_conf_0700001_blokir_otomatis():
    ip = "192.168.20.90"
    hasil = putuskan(ddos(ip, 25, conf=0.700001))
    assert ip in hasil.ip_blokir
