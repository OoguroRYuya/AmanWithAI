from datetime import datetime, timedelta

import pytest

from mitigasi import ModulMitigasi


@pytest.fixture
def m(monkeypatch):
    m = ModulMitigasi("192.0.2.1", "u", "p", dry_run=True)
    m.panggilan = []

    def catat(perintah, deskripsi):
        m.panggilan.append((list(perintah), deskripsi))
        return True

    monkeypatch.setattr(m, "_jalankan", catat)
    return m


def test_blokir_banyak_satu_sesi(m):
    ips = [f"192.168.20.{i}" for i in range(10, 250)]
    hasil = m.blokir_banyak(ips, durasi_menit=15, alasan="ddos_flood")

    assert len(m.panggilan) == 1
    perintah, deskripsi = m.panggilan[0]
    assert len(perintah) == 240
    assert all(p.startswith("set firewall group address-group BLOKIR_NDR address ") for p in perintah)
    assert "240 IP" in deskripsi
    assert hasil == sorted(ips)
    assert set(m.terblokir) == set(ips)


def test_blokir_banyak_tidak_mengirim_ulang_ip_terblokir(m):
    m.blokir_banyak(["192.168.20.10", "192.168.20.11"])
    lama = m.terblokir["192.168.20.10"]
    m.blokir_banyak(["192.168.20.10", "192.168.20.11", "192.168.20.12"], durasi_menit=30)

    assert len(m.panggilan) == 2
    assert m.panggilan[1][0] == ["set firewall group address-group BLOKIR_NDR address 192.168.20.12"]
    assert m.terblokir["192.168.20.10"] > lama  # diperpanjang


def test_blokir_banyak_semua_sudah_terblokir_tanpa_sesi(m):
    m.blokir_banyak(["192.168.20.10"])
    m.blokir_banyak(["192.168.20.10"])
    assert len(m.panggilan) == 1


def test_blokir_banyak_kosong(m):
    assert m.blokir_banyak([]) == []
    assert m.panggilan == []


def test_blokir_banyak_gagal_tidak_mencatat(monkeypatch):
    m = ModulMitigasi("192.0.2.1", "u", "p", dry_run=True)
    monkeypatch.setattr(m, "_jalankan", lambda perintah, deskripsi: False)
    assert m.blokir_banyak(["192.168.20.10"]) == []
    assert m.terblokir == {}


def test_cabut_banyak_dan_kedaluwarsa(m):
    m.blokir_banyak([f"192.168.20.{i}" for i in range(10, 15)])
    m.terblokir["192.168.20.10"] = datetime.now() - timedelta(seconds=1)
    m.terblokir["192.168.20.11"] = datetime.now() - timedelta(seconds=1)

    dicabut = m.cabut_kedaluwarsa()

    assert dicabut == ["192.168.20.10", "192.168.20.11"]
    perintah, _ = m.panggilan[-1]
    assert len(perintah) == 2
    assert all(p.startswith("delete firewall group") for p in perintah)
    assert set(m.terblokir) == {"192.168.20.12", "192.168.20.13", "192.168.20.14"}


def test_dry_run_tidak_membuka_koneksi(caplog):
    m = ModulMitigasi("192.0.2.1", "u", "p", dry_run=True)
    with caplog.at_level("INFO", logger="mitigasi"):
        assert m.blokir_banyak(["192.168.20.10", "192.168.20.11"]) == ["192.168.20.10", "192.168.20.11"]
    assert m._koneksi() is None
    assert any("[DRY RUN] memblokir 2 IP" in r.message for r in caplog.records)
