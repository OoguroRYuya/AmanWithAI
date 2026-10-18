import keputusan as kp
import pipeline
from conftest import bingkai, flow

KORBAN = "192.168.30.10"
ALLOWLIST = {"192.168.20.1", "192.168.30.1"}

PARAM = dict(
    min_flow=20, ambang_rasio=0.80, ambang_tinggi=0.90, ambang_sedang=0.70,
    allowlist=ALLOWLIST, durasi_blokir=15,
)


def putuskan(baris, **ubah):
    hw = pipeline.kelompokkan(bingkai(baris))[0]
    return kp.putuskan(hw, **{**PARAM, **ubah})


def flood_palsu(n, conf=0.97, mulai=50):
    """n sumber palsu, masing-masing hanya SATU flow serangan."""
    return [flow(f"192.168.20.{mulai + i}", KORBAN, "ddos_flood", confidence=conf)
            for i in range(n)]


def test_klien_dengan_sedikit_salah_klasifikasi_tidak_diblokir():
    klien = "192.168.10.12"
    baris = [flow(klien, KORBAN, "normal", confidence=0.95) for _ in range(200)]
    baris += [flow(klien, KORBAN, "ddos_flood", confidence=0.95) for _ in range(3)]
    baris += flood_palsu(30)
    hasil = putuskan(baris)

    [k] = hasil.keputusan
    assert k.status == kp.BLOKIR_OTOMATIS
    assert klien in k.insiden.sumber
    assert klien not in k.ip_blokir
    assert klien not in hasil.ip_blokir
    ev = {e.ip: e for e in k.evaluasi_sumber}
    assert ev[klien].rasio_serangan < 0.80
    assert not ev[klien].lolos
    assert "rasio" in ev[klien].alasan
    # narasi menyebut IP yang diblokir, bukan klien
    assert klien not in k.saran["narasi"]
    assert "192.168.20.50 dan 29 alamat lain" in k.saran["narasi"]


def test_sumber_palsu_satu_flow_tetap_diblokir():
    hasil = putuskan(flood_palsu(30))

    [k] = hasil.keputusan
    assert k.status == kp.BLOKIR_OTOMATIS
    assert len(k.ip_blokir) == 30
    assert all(e.rasio_serangan == 1.0 for e in k.evaluasi_sumber)
    assert k.saran["mitigasi_otomatis"] is True


def test_min_flow_insiden_berlaku_untuk_insiden_utuh():
    # 19 sumber palsu x 1 flow = 19 flow < MIN_FLOW_INSIDEN -> diabaikan
    hasil = putuskan(flood_palsu(19))
    assert hasil.keputusan == []
    assert hasil.jumlah_diabaikan == 1
    assert hasil.ip_blokir == []


def test_allowlist_tidak_pernah_diblokir():
    gateway = "192.168.20.1"
    baris = flood_palsu(25)
    baris += [flow(gateway, KORBAN, "ddos_flood", confidence=0.99) for _ in range(50)]
    hasil = putuskan(baris)

    [k] = hasil.keputusan
    assert k.status == kp.BLOKIR_OTOMATIS
    assert gateway not in k.ip_blokir
    assert gateway not in hasil.ip_blokir
    ev = {e.ip: e for e in k.evaluasi_sumber}
    assert ev[gateway].alasan == "ada di allowlist"


def test_allowlist_tidak_masuk_kandidat_persetujuan():
    gateway = "192.168.20.1"
    baris = [flow(gateway, KORBAN, "port_scanning", confidence=0.8, dp=p) for p in range(30)]
    hasil = putuskan(baris)

    [k] = hasil.keputusan
    assert k.status == kp.DICATAT
    assert k.ip_kandidat == [] and k.ip_blokir == []


def test_confidence_sedang_menunggu_persetujuan():
    pemindai = "192.168.20.20"
    baris = [flow(pemindai, KORBAN, "port_scanning", confidence=0.78, dp=p) for p in range(40)]
    hasil = putuskan(baris)

    [k] = hasil.keputusan
    assert k.status == kp.MENUNGGU_PERSETUJUAN
    assert k.ip_kandidat == [pemindai]
    assert k.ip_blokir == []
    assert hasil.ip_blokir == []
    assert hasil.menunggu == [k]
    assert k.saran["mitigasi_otomatis"] is False


def test_confidence_rendah_hanya_dicatat():
    baris = [flow("192.168.20.20", KORBAN, "port_scanning", confidence=0.6, dp=p)
             for p in range(40)]
    [k] = putuskan(baris).keputusan
    assert k.status == kp.DICATAT


def test_confidence_insiden_tinggi_tetapi_sumber_kurang_yakin():
    # rata-rata insiden >= 0.90, tetapi satu-satunya sumber yang rasionya
    # tinggi punya confidence rata-rata < 0.90 -> tidak otomatis
    baris = flood_palsu(30, conf=0.99)
    baris += [flow("192.168.20.200", KORBAN, "ddos_flood", confidence=0.85)
              for _ in range(5)]
    [k] = putuskan(baris).keputusan
    assert k.status == kp.BLOKIR_OTOMATIS
    assert "192.168.20.200" not in k.ip_blokir

    hanya_ragu = [flow("192.168.20.200", KORBAN, "ddos_flood", confidence=0.85)
                  for _ in range(5)]
    hanya_ragu += [flow("192.168.20.1", KORBAN, "ddos_flood", confidence=0.99)
                   for _ in range(40)]
    [k] = putuskan(hanya_ragu).keputusan
    assert k.insiden.confidence >= 0.90
    assert k.status == kp.MENUNGGU_PERSETUJUAN
    assert k.ip_kandidat == ["192.168.20.200"]
    assert "Catatan" in k.saran["narasi"]


def test_ip_blokir_digabung_antar_insiden():
    baris = flood_palsu(25, mulai=50)
    baris += [flow(f"192.168.20.{150 + i}", "192.168.30.11", "ddos_flood", confidence=0.97)
              for i in range(25)]
    baris += [flow("192.168.20.50", "192.168.30.11", "ddos_flood", confidence=0.97)]
    hasil = putuskan(baris)

    assert len(hasil.keputusan) == 2
    assert len(hasil.ip_blokir) == 50
    assert hasil.ip_blokir == sorted(set(hasil.ip_blokir))
