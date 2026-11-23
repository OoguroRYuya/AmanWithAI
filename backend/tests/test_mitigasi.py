from datetime import datetime, timedelta

import pytest

from mitigasi import ModulMitigasi


@pytest.fixture
def m(monkeypatch):
    m = ModulMitigasi("192.0.2.1", "u", "p", dry_run=True)
    m.panggilan = []

    def catat(perintah, deskripsi, **_):
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
    monkeypatch.setattr(m, "_jalankan", lambda perintah, deskripsi, **_: False)
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


# ---------------------------------------------- butir 27 dan 28: router tiruan

class RouterTiruan:
    """Koneksi Netmiko tiruan: menyimpan isi BLOKIR_NDR dan bisa dibuat gagal."""

    def __init__(self, grup=(), commit_gagal=False, abaikan=()):
        self.grup = set(grup)
        self.commit_gagal = commit_gagal
        self.abaikan = set(abaikan)     # IP yang diam-diam tidak diterapkan router
        self.tertunda = []
        self.perintah = []

    def send_config_set(self, daftar, exit_config_mode=False):
        self.tertunda = list(daftar)
        self.perintah += daftar
        return "\n".join(daftar)

    def send_command(self, perintah, expect_string=None):
        self.perintah.append(perintah)
        if perintah == "commit":
            if self.commit_gagal:
                return "[ firewall ]\nCommit failed"
            for p in self.tertunda:
                ip = p.rsplit(" ", 1)[1]
                if ip in self.abaikan:
                    continue
                (self.grup.add if p.startswith("set") else self.grup.discard)(ip)
            return ""
        if "show configuration commands" in perintah:
            return "\n".join(f"set firewall group address-group BLOKIR_NDR address '{ip}'"
                             for ip in sorted(self.grup))
        return ""

    def disconnect(self):
        pass


@pytest.fixture
def router(monkeypatch):
    def buat(**kw):
        r = RouterTiruan(**kw)
        m = ModulMitigasi("192.0.2.1", "u", "p", dry_run=False)
        monkeypatch.setattr(m, "_koneksi", lambda: r)
        return m, r
    return buat


def test_commit_gagal_tidak_dianggap_terblokir(router):
    m, r = router(commit_gagal=True)
    assert m.blokir_banyak(["192.168.20.50"]) == []
    assert m.terblokir == {}
    assert m.hasil_terakhir["tahap"] == "dikirim"
    assert "exit discard" in r.perintah


def test_blokir_terverifikasi_di_router(router):
    m, r = router()
    assert m.blokir_banyak(["192.168.20.50", "192.168.20.51"]) == ["192.168.20.50", "192.168.20.51"]
    assert m.hasil_terakhir["tahap"] == "terverifikasi" and m.hasil_terakhir["tersimpan"]
    assert r.grup == {"192.168.20.50", "192.168.20.51"}


def test_ip_yang_tidak_aktif_setelah_commit_tidak_dicatat(router):
    m, r = router(abaikan={"192.168.20.51"})
    assert m.blokir_banyak(["192.168.20.50", "192.168.20.51"]) == ["192.168.20.50"]
    assert set(m.terblokir) == {"192.168.20.50"}
    assert m.hasil_terakhir["tahap"] == "commit_ok"


def test_cabut_terverifikasi(router):
    m, r = router()
    m.blokir_banyak(["192.168.20.50"])
    assert m.cabut_banyak(["192.168.20.50"]) == ["192.168.20.50"]
    assert r.grup == set() and m.terblokir == {}


def test_timeout_ssh_tidak_mencatat(monkeypatch):
    m = ModulMitigasi("192.0.2.1", "u", "p", dry_run=False)

    def putus():
        raise TimeoutError("SSH timeout")
    monkeypatch.setattr(m, "_koneksi", putus)
    assert m.blokir_banyak(["192.168.20.50"]) == []
    assert m.terblokir == {}


def test_sinkronisasi_setelah_backend_restart(router, tmp_path, monkeypatch):
    # Router masih menyimpan .50 dan .51, berkas status backend hilang dan
    # masih mencatat .60 yang sudah dicabut manual di router
    r = RouterTiruan(grup={"192.168.20.50", "192.168.20.51"})
    m = ModulMitigasi("192.0.2.1", "u", "p", dry_run=False,
                      berkas_status=tmp_path / "terblokir.json")
    m.terblokir = {"192.168.20.60": datetime.now() + timedelta(minutes=5)}
    monkeypatch.setattr(m, "_koneksi", lambda: r)

    hasil = m.sinkronkan_router(durasi_menit=15)
    assert hasil["ditambah"] == ["192.168.20.50", "192.168.20.51"]
    assert hasil["dihapus"] == ["192.168.20.60"]
    assert set(m.terblokir) == {"192.168.20.50", "192.168.20.51"}
    # IP hasil sinkronisasi tetap punya kedaluwarsa sehingga dicabut otomatis
    assert all(w > datetime.now() for w in m.terblokir.values())


def test_sinkronisasi_router_tak_terjangkau_tidak_mengubah_daftar(monkeypatch):
    m = ModulMitigasi("192.0.2.1", "u", "p", dry_run=False)
    m.terblokir = {"192.168.20.60": datetime.now() + timedelta(minutes=5)}

    def putus():
        raise TimeoutError("SSH timeout")
    monkeypatch.setattr(m, "_koneksi", putus)
    assert m.sinkronkan_router() is None
    assert set(m.terblokir) == {"192.168.20.60"}
