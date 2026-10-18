import pandas as pd
import pytest

import ekstraksi_fitur as ef
import pipeline
from conftest import FIXTURE_CSV, SESI4_CSV, bingkai, flow

KORBAN = "192.168.30.10"


def test_ddos_dikelompokkan_per_korban():
    baris = [flow(f"192.168.20.{i}", KORBAN, "ddos_flood") for i in range(50, 80)]
    baris += [flow("192.168.20.99", "192.168.30.11", "ddos_flood")]
    hasil = pipeline.kelompokkan(bingkai(baris))

    assert len(hasil) == 1
    ddos = {i.kunci: i for i in hasil[0].insiden if i.kelas == "ddos_flood"}
    assert set(ddos) == {KORBAN, "192.168.30.11"}
    assert ddos[KORBAN].jumlah_flow == 30
    assert len(ddos[KORBAN].sumber) == 30
    assert ddos[KORBAN].tujuan == [KORBAN]


def test_scan_dikelompokkan_per_sumber():
    baris = [flow("192.168.20.20", KORBAN, "port_scanning", dp=p) for p in range(1, 26)]
    baris += [flow("192.168.20.20", "192.168.30.11", "port_scanning", dp=p) for p in range(1, 6)]
    baris += [flow("192.168.20.21", KORBAN, "port_scanning", dp=p) for p in range(1, 4)]
    hasil = pipeline.kelompokkan(bingkai(baris))

    scan = {i.kunci: i for i in hasil[0].insiden}
    assert set(scan) == {"192.168.20.20", "192.168.20.21"}
    assert scan["192.168.20.20"].jumlah_flow == 30
    assert scan["192.168.20.20"].tujuan == [KORBAN, "192.168.30.11"]
    assert scan["192.168.20.20"].sumber == ["192.168.20.20"]


def test_flow_normal_tidak_membentuk_insiden():
    baris = [flow("192.168.10.10", KORBAN, "normal") for _ in range(100)]
    hasil = pipeline.kelompokkan(bingkai(baris))[0]

    assert hasil.insiden == []
    assert hasil.per_kelas == {"normal": 100, "ddos_flood": 0, "port_scanning": 0}


def test_per_sumber_dan_confidence():
    baris = [flow("192.168.10.12", KORBAN, "normal", confidence=0.9) for _ in range(7)]
    baris += [flow("192.168.10.12", KORBAN, "ddos_flood", confidence=0.8) for _ in range(3)]
    hasil = pipeline.kelompokkan(bingkai(baris))[0]

    s = hasil.per_sumber["192.168.10.12"]
    assert (s["normal"], s["ddos_flood"], s["total"], s["serangan"]) == (7, 3, 10, 3)
    assert s["conf_serangan"] == pytest.approx(2.4)
    assert hasil.insiden[0].confidence == pytest.approx(0.8)


def test_jendela_terpisah():
    baris = [flow("192.168.20.50", KORBAN, "ddos_flood", window=w) for w in (100, 100, 101)]
    hasil = pipeline.kelompokkan(bingkai(baris))

    assert [h.window_epoch for h in hasil] == [6000, 6060]
    assert [h.insiden[0].jumlah_flow for h in hasil] == [2, 1]


def test_tandai_backscatter():
    da = pd.Series(["192.168.20.5", "192.168.30.10", "192.168.20.255", "bukan-ip"])
    assert pipeline.tandai_backscatter(da).tolist() == [True, False, True, False]


def test_potong_per_window_fixture_satu_jendela():
    potongan = pipeline.potong_per_window(FIXTURE_CSV)
    assert len(potongan) == 1
    w, isi = potongan[0]
    assert isi.decode() == FIXTURE_CSV.read_text()


@pytest.mark.skipif(not SESI4_CSV.exists(), reason="flows_sesi4.csv tidak tersedia")
def test_potong_per_window_fitur_sama_dengan_file_utuh(tmp_path):
    """Replay per jendela harus menghasilkan fitur yang sama dengan file utuh."""
    utuh = ef.ekstrak(SESI4_CSV, sertakan_ip=True)
    bagian = []
    for i, (w, isi) in enumerate(pipeline.potong_per_window(SESI4_CSV)):
        p = tmp_path / f"w{i}.csv"
        p.write_bytes(isi)
        bagian.append(ef.ekstrak(p, sertakan_ip=True))
    gabung = pd.concat(bagian, ignore_index=True)

    kunci = ["window", "sa", "da", "dp", "duration", "byte_count"]
    a = utuh.sort_values(kunci, kind="stable").reset_index(drop=True)
    b = gabung.sort_values(kunci, kind="stable").reset_index(drop=True)
    pd.testing.assert_frame_equal(a, b)


def test_proses_csv_fixture(model):
    hasil = pipeline.proses_csv(FIXTURE_CSV, model)
    assert len(hasil) == 1
    hw = hasil[0]

    total = sum(hw.per_kelas.values())
    assert hw.jumlah_backscatter > 0
    assert total + hw.jumlah_backscatter == len(ef.ekstrak(FIXTURE_CSV))
    # backscatter dibuang sebelum prediksi: tidak ada sumber dari Target
    # yang menuju subnet penyerang
    assert all(i.tujuan and not any(t.startswith("192.168.20.") for t in i.tujuan)
               for i in hw.insiden)
    # dikelompokkan: jauh lebih sedikit insiden daripada flow serangan
    serangan = hw.per_kelas["ddos_flood"] + hw.per_kelas["port_scanning"]
    assert 0 < len(hw.insiden) < serangan
    assert {i.kelas for i in hw.insiden} <= {"ddos_flood", "port_scanning"}
