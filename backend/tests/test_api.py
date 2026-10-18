"""Uji ujung ke ujung: POST /api/ingest -> pekerja -> riwayat insiden."""

import time

import pytest

from conftest import FIXTURE_CSV, MODEL_PATH

pytestmark = pytest.mark.skipif(not MODEL_PATH.exists(), reason="model tidak tersedia")

STEMPEL = ("t_window_end", "t_diterima", "t_klasifikasi", "t_mitigasi")


def tunggu_antrean(klien, batas=60):
    akhir = time.time() + batas
    while time.time() < akhir:
        s = klien.get("/api/status").json()
        if s["antrean"] == 0 and klien.get("/api/trafik").json()["total"] > 0:
            return
        time.sleep(0.2)
    raise AssertionError("antrean tidak selesai diproses")


@pytest.fixture(scope="module")
def insiden(klien):
    r = klien.post(
        "/api/ingest",
        content=FIXTURE_CSV.read_bytes(),
        headers={"Content-Type": "text/csv", "X-Nama-File": "nfcapd.202610160942"},
    )
    assert r.status_code == 202
    tunggu_antrean(klien)
    return klien.get("/api/riwayat", params={"jenis": "insiden", "limit": 500}).json()["data"]


def test_status_dry_run(klien):
    s = klien.get("/api/status").json()
    assert s["model_dimuat"] and s["dry_run"] is True


def test_ingest_menghasilkan_insiden_terkelompok(klien, insiden):
    assert insiden
    trafik = klien.get("/api/trafik").json()["data"][-1]
    serangan = trafik["per_kelas"]["ddos_flood"] + trafik["per_kelas"]["port_scanning"]
    assert len(insiden) < serangan
    for e in insiden:
        assert e["jenis"] == "insiden"
        assert e["nama_file"] == "nfcapd.202610160942"
        for k in STEMPEL:
            assert k in e
        assert e["t_window_end"] and e["t_diterima"] and e["t_klasifikasi"]
        if e["status"] == "blokir_otomatis":
            assert e["t_mitigasi"] and e["dimitigasi"]


def test_allowlist_tidak_diblokir(klien, insiden):
    import konfigurasi as cfg
    terblokir = {d["ip"] for d in klien.get("/api/terblokir").json()["data"]}
    assert not (terblokir & cfg.ALLOWLIST)
    assert not any(ip.startswith("192.168.10.") for ip in terblokir)


def test_id_unik(insiden):
    ids = [e["id"] for e in insiden]
    assert len(ids) == len(set(ids))


def test_ingest_kosong_ditolak(klien):
    r = klien.post("/api/ingest", content=b"  \n", headers={"Content-Type": "text/csv"})
    assert r.status_code == 400


def test_ingest_multipart(klien):
    r = klien.post("/api/ingest", files={"file": ("x.csv", FIXTURE_CSV.read_bytes(), "text/csv")})
    assert r.status_code == 202
    assert r.json()["nama"] == "x.csv"
    tunggu_antrean(klien)


def test_ingest_path_di_luar_folder_ditolak(klien):
    r = klien.post("/api/ingest", json={"path": str(FIXTURE_CSV)})
    assert r.status_code == 403


def tunggu_persetujuan(klien, minimal, batas=60):
    akhir = time.time() + batas
    while time.time() < akhir:
        menunggu = klien.get("/api/persetujuan").json()["data"]
        if len(menunggu) >= minimal:
            return menunggu
        time.sleep(0.2)
    raise AssertionError(f"kurang dari {minimal} insiden menunggu persetujuan")


def test_setujui_dan_tolak(klien, insiden, monkeypatch):
    import konfigurasi as cfg
    # Dengan ambang default seluruh insiden fixture diblokir otomatis;
    # ambang > 1 memaksa sumbernya masuk antrean persetujuan
    monkeypatch.setattr(cfg, "AMBANG_CONF_BLOKIR", 1.01)
    r = klien.post("/api/ingest", content=FIXTURE_CSV.read_bytes(),
                   headers={"Content-Type": "text/csv"})
    assert r.status_code == 202
    a, b = tunggu_persetujuan(klien, 2)[:2]

    r = klien.post(f"/api/mitigasi/setujui/{a['id']}")
    assert r.status_code == 200
    hasil = r.json()
    assert hasil["status"] == "disetujui" and hasil["dimitigasi"]
    assert hasil["t_mitigasi"] and hasil["latensi_detik"]["mitigasi"] is not None
    terblokir = {d["ip"] for d in klien.get("/api/terblokir").json()["data"]}
    assert set(a["ip_kandidat"]) <= terblokir

    r = klien.post(f"/api/mitigasi/tolak/{b['id']}")
    assert r.status_code == 200 and r.json()["status"] == "ditolak"

    assert klien.post(f"/api/mitigasi/setujui/{a['id']}").status_code == 409
    assert klien.post(f"/api/mitigasi/tolak/{b['id']}").status_code == 409
    assert klien.post("/api/mitigasi/setujui/999999").status_code == 404
