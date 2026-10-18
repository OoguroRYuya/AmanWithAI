"""Uji umpan real-time WebSocket /ws dan pengelola koneksi ws.KoneksiWS."""

import asyncio
import json
import time

import pytest

import ws as modul_ws
from conftest import FIXTURE_CSV, MODEL_PATH


class SoketPalsu:
    def __init__(self, perilaku="hidup"):
        self.perilaku = perilaku
        self.diterima = []

    async def send_text(self, teks):
        if self.perilaku == "mati":
            raise RuntimeError("Cannot call send once a close message has been sent")
        if self.perilaku == "macet":
            await asyncio.sleep(10)
        self.diterima.append(json.loads(teks))


def test_broadcast_buang_klien_mati_dan_tetap_kirim_ke_yang_hidup(monkeypatch):
    monkeypatch.setattr(modul_ws, "BATAS_KIRIM_DETIK", 0.05)
    hidup1, mati, macet, hidup2 = (SoketPalsu(), SoketPalsu("mati"),
                                   SoketPalsu("macet"), SoketPalsu())

    async def jalan():
        k = modul_ws.KoneksiWS()
        k.aktif.update({hidup1, mati, macet, hidup2})
        await k.broadcast({"tipe": "trafik", "window": "w1"})
        await k.broadcast({"tipe": "trafik", "window": "w2"})
        return k

    k = asyncio.run(jalan())
    assert k.aktif == {hidup1, hidup2}
    for s in (hidup1, hidup2):
        assert [p["window"] for p in s.diterima] == ["w1", "w2"]


def test_broadcast_tanpa_klien_tidak_galat():
    asyncio.run(modul_ws.KoneksiWS().broadcast({"tipe": "ping"}))


def terima_sampai(ws, tipe_dicari, batas=200):
    """Membaca pesan sampai seluruh tipe_dicari muncul; mengembalikan per tipe."""
    terkumpul = {}
    for _ in range(batas):
        pesan = ws.receive_json()
        terkumpul.setdefault(pesan["tipe"], []).append(pesan)
        if tipe_dicari <= terkumpul.keys():
            return terkumpul
    raise AssertionError(f"tipe {tipe_dicari - terkumpul.keys()} tidak diterima")


@pytest.mark.skipif(not MODEL_PATH.exists(), reason="model tidak tersedia")
def test_snapshot_lalu_umpan_live(klien):
    with klien.websocket_connect("/ws") as ws:
        snap = ws.receive_json()
        assert snap["tipe"] == "snapshot"
        assert set(snap) == {"tipe", "status", "insiden", "terblokir", "trafik"}
        assert snap["status"]["dry_run"] is True

        r = klien.post(
            "/api/ingest",
            content=FIXTURE_CSV.read_bytes(),
            headers={"Content-Type": "text/csv", "X-Nama-File": "nfcapd.ws"},
        )
        assert r.status_code == 202
        m = terima_sampai(ws, {"trafik", "insiden", "mitigasi", "status"})

    [t] = m["trafik"]
    assert {"window", "per_kelas", "byte_total", "jumlah_backscatter"} <= t.keys()

    # pesan insiden = entri riwayat yang sama ditambah "tipe"
    riwayat = {e["id"]: e for e in
               klien.get("/api/riwayat", params={"jenis": "insiden", "limit": 500}).json()["data"]}
    for ins in m["insiden"]:
        assert ins["nama_file"] == "nfcapd.ws"
        tersimpan = riwayat[ins["id"]]
        assert {k: v for k, v in ins.items() if k != "tipe"} == tersimpan

    mit = m["mitigasi"][0]
    assert mit["aksi"] == "blokir" and mit["oleh"] == "otomatis" and mit["dry_run"] is True
    diblokir = {ip for ins in m["insiden"] if ins["status"] == "blokir_otomatis"
                for ip in ins["ip_blokir"]}
    assert set(mit["ip"]) == diblokir
    assert set(m["status"][-1]) == {"tipe", "model_dimuat", "dry_run", "ip_terblokir"}


def test_snapshot_memuat_keadaan_terkini(klien):
    with klien.websocket_connect("/ws") as ws:
        snap = ws.receive_json()
    # /api/trafik default limit 60 = SNAPSHOT_TRAFIK
    assert snap["trafik"] == klien.get("/api/trafik").json()["data"]
    assert snap["terblokir"] == klien.get("/api/terblokir").json()["data"]
    assert all(e["jenis"] == "insiden" for e in snap["insiden"])


def test_mitigasi_manual_disiarkan(klien):
    ip = "192.168.20.250"
    with klien.websocket_connect("/ws") as ws:
        ws.receive_json()  # snapshot

        assert klien.post("/api/mitigasi/blokir", json={"ip": ip}).status_code == 200
        m = terima_sampai(ws, {"mitigasi"})
        assert m["mitigasi"][0] == {"tipe": "mitigasi", "aksi": "blokir", "ip": [ip],
                                    "oleh": "manual", "dry_run": True}

        assert klien.post("/api/mitigasi/cabut", json={"ip": ip}).status_code == 200
        m = terima_sampai(ws, {"mitigasi"})
        assert m["mitigasi"][0]["aksi"] == "cabut" and m["mitigasi"][0]["ip"] == [ip]


def test_klien_putus_dilepas(klien):
    import main
    awal = len(main.koneksi_ws.aktif)
    with klien.websocket_connect("/ws") as ws:
        ws.receive_json()
        assert len(main.koneksi_ws.aktif) == awal + 1
    akhir = time.time() + 5
    while len(main.koneksi_ws.aktif) > awal and time.time() < akhir:
        time.sleep(0.05)
    assert len(main.koneksi_ws.aktif) == awal
