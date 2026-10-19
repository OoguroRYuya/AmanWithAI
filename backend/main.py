"""
main.py
=======
Backend API untuk dashboard sistem NDR.

Menyatukan tiga komponen inti penelitian:
    1. Klasifikasi trafik menggunakan model machine learning terlatih
    2. Penyusunan narasi saran tindakan berbasis template
    3. Eksekusi mitigasi otomatis ke router melalui Netmiko

Alur live (fase 2):
    CSV NetFlow per jendela 60 detik masuk lewat POST /api/ingest (dari
    kirim_flow.sh di host VM GNS3) atau dari mode replay (SUMBER=replay).
    Pekerja latar belakang mengambilnya dari antrean, menjalankan
    pipeline.proses_csv -> keputusan.putuskan, menyimpan insiden ke riwayat,
    lalu memblokir sumber yang lolos gerbang dalam satu sesi Netmiko.

Umpan real-time (fase 3):
    Klien WebSocket /ws menerima satu pesan `snapshot`, lalu pesan
    `trafik`, `insiden`, `mitigasi`, `status`, dan `ping` secara langsung.
    Endpoint REST tetap dipakai untuk pemuatan awal halaman.

Menjalankan:
    uvicorn main:app --reload --host 0.0.0.0 --port 8000

Dokumentasi API otomatis tersedia di:
    http://localhost:8000/docs
"""

import asyncio
import itertools
import logging
import os
import sys
import tempfile
from collections import deque
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

import konfigurasi as cfg
import keputusan as kp
import pipeline
from ws import KoneksiWS

# Menambahkan folder ml ke path agar modul penelitian dapat diimpor
sys.path.insert(0, str(cfg.DIR_REPO / "ml"))

from mitigasi import ModulMitigasi          # noqa: E402
from saran_tindakan import susun_saran      # noqa: E402

log = logging.getLogger("ndr")

FITUR = [
    "duration", "packet_count", "byte_count", "dst_port_count",
    "avg_packet_size", "flow_rate", "syn_flag_count",
    "unique_src_ip_per_dst", "protocol", "inter_arrival_time",
]

MAKS_RIWAYAT = 500
MAKS_TRAFIK = 240          # 4 jam jendela 60 detik
MAKS_PERSETUJUAN = 200
INTERVAL_PING_DETIK = 20
SNAPSHOT_INSIDEN = 50
SNAPSHOT_TRAFIK = 60

# Penyimpanan sementara di memori. Untuk penggunaan jangka panjang,
# sebaiknya diganti dengan basis data.
riwayat_deteksi: List[dict] = []
trafik: deque = deque(maxlen=MAKS_TRAFIK)
antrean_persetujuan: dict = {}      # {id: entri insiden menunggu persetujuan}
model = None
label_kelas = None
mitigator: Optional[ModulMitigasi] = None
koneksi_ws: Optional[KoneksiWS] = None

# Penghitung id monoton: id tidak berulang meski riwayat dipangkas
_penghitung_id = itertools.count(1)

# Antrean CSV per jendela dan kunci akses router. Semua pemanggilan
# mitigator lewat _mitigasi() agar Netmiko berjalan di thread terpisah
# dan dict `terblokir` tidak pernah diubah dari dua tempat sekaligus.
antrean: asyncio.Queue = asyncio.Queue()
kunci_mitigasi = asyncio.Lock()

status_replay = {"aktif": False, "total_window": 0, "terkirim": 0, "selesai": False}


# ---------------------------------------------------------------- utilitas


def _sekarang():
    return datetime.now()


def _iso(waktu):
    return waktu.isoformat(timespec="milliseconds") if waktu else None


def _selisih_detik(akhir, awal):
    if akhir is None or awal is None:
        return None
    return round((akhir - awal).total_seconds(), 3)


def _catat(entri):
    """Menyimpan entri ke riwayat (terbaru di depan) dengan id monoton."""
    entri.setdefault("id", next(_penghitung_id))
    riwayat_deteksi.insert(0, entri)
    del riwayat_deteksi[MAKS_RIWAYAT:]
    return entri


async def _mitigasi(fungsi, *args, **kwargs):
    """Menjalankan aksi mitigator di thread terpisah, satu per satu."""
    async with kunci_mitigasi:
        return await asyncio.to_thread(fungsi, *args, **kwargs)


# Siaran WebSocket selalu dipanggil di luar kunci_mitigasi dan di luar
# asyncio.to_thread, langsung dari event loop


async def _siarkan(pesan):
    if koneksi_ws:
        await koneksi_ws.broadcast(pesan)


async def _siarkan_mitigasi(aksi, ips, oleh):
    await _siarkan({
        "tipe": "mitigasi",
        "aksi": aksi,
        "ip": list(ips),
        "oleh": oleh,
        "dry_run": cfg.DRY_RUN,
    })
    await _siarkan_status()


async def _siarkan_status():
    await _siarkan({
        "tipe": "status",
        "model_dimuat": model is not None,
        "dry_run": cfg.DRY_RUN,
        "ip_terblokir": len(mitigator.terblokir) if mitigator else 0,
    })


async def _siarkan_insiden(entri):
    await _siarkan({"tipe": "insiden", **entri})


# --------------------------------------------------------- pekerja antrean


async def pekerja_antrean():
    """Memproses CSV dari antrean satu per satu, berurutan."""
    while True:
        item = await antrean.get()
        try:
            await _proses_item(item)
        except Exception as e:
            log.exception(f"Gagal memproses {item.get('nama')}: {e}")
            _catat({
                "waktu": _iso(_sekarang()),
                "jenis": "galat_ingest",
                "keterangan": f"Gagal memproses {item.get('nama')}: {e}",
            })
        finally:
            antrean.task_done()


async def _proses_item(item):
    if model is None:
        raise RuntimeError("model belum dimuat")

    # pipeline membaca dari path, jadi isi CSV ditulis ke file sementara
    fd, path = tempfile.mkstemp(suffix=".csv", prefix="ndr_")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(item["isi"])
        hasil_list = await asyncio.to_thread(pipeline.proses_csv, path, model)
    finally:
        os.remove(path)
    t_klasifikasi = _sekarang()

    for hw in hasil_list:
        await _proses_window(hw, item, t_klasifikasi)


async def _proses_window(hw, item, t_klasifikasi):
    kep = kp.putuskan(hw)

    # Mode ingest: akhir jendela diambil dari stempel waktu flow (jam
    # Collector). Mode replay: saat potongan jendela dikirim pemutar,
    # yang mensimulasikan nfcapd menutup file.
    t_window_end = item.get("t_window_end") or pipeline.akhir_window(hw.window_epoch).to_pydatetime()
    t_diterima = item["t_diterima"]

    entri_trafik = {
        "window": hw.window,
        "per_kelas": hw.per_kelas,
        "byte_total": hw.byte_total,
        "jumlah_backscatter": hw.jumlah_backscatter,
        "jumlah_insiden": len(kep.keputusan),
        "jumlah_diabaikan": kep.jumlah_diabaikan,
        "sumber_data": item["sumber"],
        "t_window_end": _iso(t_window_end),
        "t_diterima": _iso(t_diterima),
        "t_klasifikasi": _iso(t_klasifikasi),
    }
    trafik.append(entri_trafik)
    await _siarkan({"tipe": "trafik", **entri_trafik})

    entri_list = []
    for k in kep.keputusan:
        d = k.ke_dict()
        ins = d.pop("insiden")
        entri = _catat({
            "waktu": _iso(_sekarang()),
            "jenis": "insiden",
            **ins,
            "jumlah_sumber": len(ins["sumber"]),
            **d,
            "dimitigasi": False,
            "sumber_data": item["sumber"],
            "nama_file": item.get("nama"),
            "t_window_end": _iso(t_window_end),
            "t_diterima": _iso(t_diterima),
            "t_klasifikasi": _iso(t_klasifikasi),
            "t_mitigasi": None,
            "latensi_detik": {
                "deteksi": _selisih_detik(t_klasifikasi, t_window_end),
                "mitigasi": None,
            },
        })
        entri["_t_window_end"] = t_window_end
        entri_list.append(entri)

        if k.status == kp.MENUNGGU_PERSETUJUAN:
            antrean_persetujuan[entri["id"]] = entri
            while len(antrean_persetujuan) > MAKS_PERSETUJUAN:
                antrean_persetujuan.pop(next(iter(antrean_persetujuan)))

    # Seluruh IP blokir otomatis dari jendela ini dikirim dalam satu sesi
    ips = kep.ip_blokir
    diblokir = set()
    if ips and mitigator:
        alasan = ", ".join(sorted({
            f"{e['kelas']} {e['kunci']}" for e in entri_list
            if e["status"] == kp.BLOKIR_OTOMATIS
        }))
        diblokir = set(await _mitigasi(
            mitigator.blokir_banyak, ips, cfg.DURASI_BLOKIR_MENIT, alasan
        ))
        t_mitigasi = _sekarang()
        for e in entri_list:
            if e["status"] == kp.BLOKIR_OTOMATIS:
                e["dimitigasi"] = bool(diblokir) and set(e["ip_blokir"]) <= diblokir
                e["t_mitigasi"] = _iso(t_mitigasi)
                e["latensi_detik"]["mitigasi"] = _selisih_detik(t_mitigasi, e["_t_window_end"])

    for e in entri_list:
        del e["_t_window_end"]

    # Insiden disiarkan setelah mitigasi agar dimitigasi/t_mitigasi sudah final
    for e in entri_list:
        await _siarkan_insiden(e)
    if diblokir:
        await _siarkan_mitigasi("blokir", sorted(diblokir), "otomatis")
    else:
        await _siarkan_status()

    log.info(
        f"Jendela {hw.window}: {hw.per_kelas}, {len(kep.keputusan)} insiden "
        f"({kep.jumlah_diabaikan} diabaikan < MIN_FLOW_INSIDEN), "
        f"{len(ips)} IP diblokir otomatis, {len(kep.menunggu)} menunggu persetujuan"
    )


# ------------------------------------------------------------- mode replay


async def pemutar_replay():
    """Memotong REPLAY_CSV per jendela 60 detik dan memasukkannya ke antrean."""
    status_replay["aktif"] = True
    potongan = await asyncio.to_thread(pipeline.potong_per_window, cfg.REPLAY_CSV)
    status_replay["total_window"] = len(potongan)
    log.info(
        f"Replay {cfg.REPLAY_CSV.name}: {len(potongan)} jendela, "
        f"1 jendela per {cfg.REPLAY_INTERVAL_DETIK} detik"
    )

    for window_idx, isi in potongan:
        t = _sekarang()
        await antrean.put({
            "isi": isi,
            "sumber": "replay",
            "nama": f"replay {pipeline.label_window(window_idx)}",
            "t_diterima": t,
            "t_window_end": t,
        })
        status_replay["terkirim"] += 1
        await asyncio.sleep(cfg.REPLAY_INTERVAL_DETIK)

    status_replay["selesai"] = True
    log.info("Replay selesai dikirim ke antrean")


# ------------------------------------------------------------- siklus hidup


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Memuat model dan menyiapkan modul mitigasi saat server dinyalakan."""
    global model, label_kelas, mitigator, koneksi_ws

    try:
        import joblib
        model = joblib.load(cfg.MODEL_PATH)
        # Daftar kelas diambil langsung dari model agar selalu konsisten
        label_kelas = [str(k) for k in model.classes_]
        print(f"Model dimuat: {cfg.MODEL_PATH.name}")
        print(f"Kelas: {label_kelas}")
    except Exception as e:
        print(f"PERINGATAN: model gagal dimuat ({e})")
        print("Endpoint /api/deteksi tidak akan berfungsi sampai model tersedia.")

    mitigator = ModulMitigasi(
        host=cfg.ROUTER_HOST,
        username=cfg.ROUTER_USER,
        password=cfg.ROUTER_PASS,
        dry_run=cfg.DRY_RUN,
    )
    print(f"Modul mitigasi siap (router={cfg.ROUTER_HOST}, dry_run={cfg.DRY_RUN})")
    print(f"Sumber data: {cfg.SUMBER}, estimasi_paket_paksa={cfg.ESTIMASI_PAKET_PAKSA}")

    koneksi_ws = KoneksiWS()

    tugas = [
        asyncio.create_task(pengirim_ping()),
        # Tugas latar belakang untuk mencabut blokir yang sudah kedaluwarsa
        asyncio.create_task(pencabut_berkala()),
        asyncio.create_task(pekerja_antrean()),
    ]
    if cfg.SUMBER == "replay":
        tugas.append(asyncio.create_task(pemutar_replay()))

    yield

    for t in tugas:
        t.cancel()


async def pencabut_berkala():
    """Memeriksa dan mencabut pemblokiran kedaluwarsa setiap satu menit."""
    while True:
        await asyncio.sleep(60)
        if mitigator:
            dicabut = await _mitigasi(mitigator.cabut_kedaluwarsa)
            if dicabut:
                await _siarkan_mitigasi("cabut", dicabut, "otomatis")
            for ip in dicabut:
                _catat({
                    "waktu": _iso(_sekarang()),
                    "jenis": "pencabutan_otomatis",
                    "src_ip": ip,
                    "keterangan": "Blokir dicabut karena durasi berakhir",
                })


async def pengirim_ping():
    """Pesan ping berkala agar koneksi WebSocket diam tidak diputus proksi."""
    while True:
        await asyncio.sleep(INTERVAL_PING_DETIK)
        await _siarkan({"tipe": "ping", "waktu": _iso(_sekarang())})


# --------------------------------------------------------------- aplikasi

app = FastAPI(
    title="Sistem Dashboard Keamanan Jaringan NDR",
    description="API deteksi dan mitigasi serangan siber pada jaringan kampus",
    version="1.1.0",
    lifespan=lifespan,
)

# CORS diperlukan agar frontend Next.js pada port berbeda dapat mengakses API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ----------------------------------------------------------------- skema


class FlowInput(BaseModel):
    """Satu flow record yang akan diklasifikasikan."""
    src_ip: str
    dst_ip: str
    duration: float = 0.0
    packet_count: int = 0
    byte_count: int = 0
    dst_port_count: int = 0
    avg_packet_size: float = 0.0
    flow_rate: float = 0.0
    syn_flag_count: int = 0
    unique_src_ip_per_dst: int = 0
    protocol: int = 6
    inter_arrival_time: float = 0.0


class MitigasiRequest(BaseModel):
    ip: str
    durasi_menit: int = 15
    alasan: str = ""


# --------------------------------------------------------------- endpoint


@app.get("/api/status")
async def status():
    """Status kesiapan sistem."""
    return {
        "model_dimuat": model is not None,
        "kelas": label_kelas,
        "router": cfg.ROUTER_HOST,
        "dry_run": cfg.DRY_RUN,
        "ambang_tinggi": cfg.AMBANG_TINGGI,
        "ambang_sedang": cfg.AMBANG_SEDANG,
        "min_flow_insiden": cfg.MIN_FLOW_INSIDEN,
        "ambang_rasio_serangan": cfg.AMBANG_RASIO_SERANGAN,
        "ambang_conf_blokir": cfg.AMBANG_CONF_BLOKIR,
        "allowlist": sorted(cfg.ALLOWLIST),
        "sumber_data": cfg.SUMBER,
        "estimasi_paket_paksa": cfg.ESTIMASI_PAKET_PAKSA,
        "replay": status_replay if cfg.SUMBER == "replay" else None,
        "antrean": antrean.qsize(),
        "menunggu_persetujuan": len(antrean_persetujuan),
        "total_deteksi": len(riwayat_deteksi),
        "ip_terblokir": len(mitigator.terblokir) if mitigator else 0,
    }


@app.post("/api/ingest", status_code=202)
async def ingest(request: Request):
    """
    Menerima satu CSV NetFlow (output nfdump) untuk diproses pekerja.

    Tiga bentuk masukan:
        - multipart/form-data dengan field `file`
        - application/json {"path": "..."}; path harus berada di INGEST_DIR
        - badan mentah berisi teks CSV (dipakai kirim_flow.sh:
          curl --data-binary @-), nama file opsional di header X-Nama-File
    """
    t_diterima = _sekarang()
    jenis = request.headers.get("content-type", "")

    if jenis.startswith("multipart/form-data"):
        form = await request.form()
        berkas = form.get("file")
        if berkas is None or not hasattr(berkas, "read"):
            raise HTTPException(400, "Field 'file' tidak ditemukan")
        isi = await berkas.read()
        nama = berkas.filename
    elif jenis.startswith("application/json"):
        data = await request.json()
        if not isinstance(data, dict) or not data.get("path"):
            raise HTTPException(400, "JSON harus berisi 'path'")
        p = Path(data["path"])
        p = (p if p.is_absolute() else cfg.DIR_REPO / p).resolve()
        if not p.is_relative_to(cfg.INGEST_DIR.resolve()):
            raise HTTPException(403, f"Path harus berada di {cfg.INGEST_DIR}")
        if not p.is_file():
            raise HTTPException(404, f"File tidak ditemukan: {p}")
        isi = p.read_bytes()
        nama = p.name
    else:
        isi = await request.body()
        nama = request.headers.get("x-nama-file", "body")

    if not isi.strip():
        raise HTTPException(400, "CSV kosong")

    await antrean.put({
        "isi": isi,
        "sumber": "ingest",
        "nama": nama,
        "t_diterima": t_diterima,
    })
    return {"diterima": True, "nama": nama, "ukuran_byte": len(isi), "antrean": antrean.qsize()}


@app.post("/api/deteksi")
async def deteksi(flow: FlowInput):
    """
    Mengklasifikasikan satu flow record, menyusun saran tindakan, dan
    menjalankan mitigasi otomatis bila tingkat kepercayaan memadai.
    """
    if model is None:
        raise HTTPException(503, "Model belum dimuat")

    import pandas as pd

    X = pd.DataFrame([[getattr(flow, f) for f in FITUR]], columns=FITUR)

    kelas = model.predict(X)[0]

    # Tingkat kepercayaan diambil dari probabilitas kelas terpilih
    confidence = 1.0
    if hasattr(model, "predict_proba"):
        try:
            proba = model.predict_proba(X)[0]
            confidence = float(max(proba))
        except Exception:
            pass

    saran = susun_saran(
        kelas=kelas,
        src_ip=flow.src_ip,
        dst_ip=flow.dst_ip,
        confidence=confidence,
        packet_count=flow.packet_count,
        byte_count=flow.byte_count,
        flow_rate=flow.flow_rate,
        dst_port_count=flow.dst_port_count,
        ambang_tinggi=cfg.AMBANG_TINGGI,
        ambang_sedang=cfg.AMBANG_SEDANG,
    )

    entri = {
        "id": next(_penghitung_id),
        "waktu": datetime.now().isoformat(),
        "jenis": "deteksi",
        "src_ip": flow.src_ip,
        "dst_ip": flow.dst_ip,
        "kelas": kelas,
        "confidence": confidence,
        "saran": saran,
        "dimitigasi": False,
    }

    # Mitigasi otomatis hanya dijalankan bila kelas merupakan serangan
    # dan tingkat kepercayaan melewati ambang yang ditetapkan.
    # Alamat pada allowlist (gateway, Collector, backend) tidak pernah diblokir.
    if saran["mitigasi_otomatis"] and mitigator and flow.src_ip not in cfg.ALLOWLIST:
        berhasil = await _mitigasi(
            mitigator.blokir,
            flow.src_ip,
            durasi_menit=saran.get("durasi_blokir", 15),
            alasan=kelas,
        )
        entri["dimitigasi"] = berhasil
        if berhasil:
            await _siarkan_mitigasi("blokir", [flow.src_ip], "otomatis")

    return _catat(entri)


@app.get("/api/riwayat")
async def riwayat(limit: int = 50, jenis: Optional[str] = None):
    """Riwayat deteksi terbaru. `jenis` opsional, misalnya `insiden`."""
    data = riwayat_deteksi
    if jenis:
        data = [d for d in data if d.get("jenis") == jenis]
    return {"total": len(data), "data": data[:limit]}


@app.get("/api/trafik")
async def daftar_trafik(limit: int = 60):
    """Jumlah flow per kelas untuk tiap jendela 60 detik (terbaru di akhir)."""
    data = list(trafik)[-limit:]
    return {"total": len(trafik), "data": data}


@app.get("/api/persetujuan")
async def daftar_persetujuan():
    """Insiden yang menunggu persetujuan administrator (terlama di depan)."""
    return {"data": list(antrean_persetujuan.values())}


@app.get("/api/ringkasan")
async def ringkasan():
    """Ringkasan statistik untuk ditampilkan pada dashboard."""
    deteksi_saja = [d for d in riwayat_deteksi if d.get("jenis") == "deteksi"]
    insiden = [d for d in riwayat_deteksi if d.get("jenis") == "insiden"]

    per_kelas = {}
    for d in deteksi_saja:
        k = d.get("kelas", "tidak diketahui")
        per_kelas[k] = per_kelas.get(k, 0) + 1

    trafik_per_kelas = {}
    for t in trafik:
        for k, n in t["per_kelas"].items():
            trafik_per_kelas[k] = trafik_per_kelas.get(k, 0) + n

    insiden_per_status = {}
    insiden_per_kelas = {}
    for d in insiden:
        insiden_per_status[d["status"]] = insiden_per_status.get(d["status"], 0) + 1
        insiden_per_kelas[d["kelas"]] = insiden_per_kelas.get(d["kelas"], 0) + 1

    return {
        "total_deteksi": len(deteksi_saja),
        "per_kelas": per_kelas,
        "total_mitigasi": sum(1 for d in deteksi_saja + insiden if d.get("dimitigasi")),
        "ip_terblokir": mitigator.daftar_terblokir() if mitigator else [],
        "trafik_per_kelas": trafik_per_kelas,
        "total_insiden": len(insiden),
        "insiden_per_status": insiden_per_status,
        "insiden_per_kelas": insiden_per_kelas,
    }


@app.get("/api/terblokir")
async def terblokir():
    """Daftar alamat IP yang sedang diblokir."""
    if not mitigator:
        raise HTTPException(503, "Modul mitigasi belum siap")
    return {"data": mitigator.daftar_terblokir()}


@app.post("/api/mitigasi/blokir")
async def blokir_manual(req: MitigasiRequest):
    """Memblokir alamat IP secara manual atas persetujuan administrator."""
    if not mitigator:
        raise HTTPException(503, "Modul mitigasi belum siap")

    # --- guard: IP di allowlist tidak boleh diblokir (gateway/collector/host) ---
    if req.ip in cfg.ALLOWLIST:
        raise HTTPException(400, f"{req.ip} ada di allowlist dan tidak boleh diblokir")

    berhasil = await _mitigasi(mitigator.blokir, req.ip, req.durasi_menit, req.alasan)

    _catat({
        "waktu": datetime.now().isoformat(),
        "jenis": "mitigasi_manual",
        "src_ip": req.ip,
        "keterangan": f"Diblokir manual selama {req.durasi_menit} menit",
    })
    await _siarkan_mitigasi("blokir", [req.ip], "manual")

    return {"status": "berhasil", "ip": req.ip}


@app.post("/api/mitigasi/cabut")
async def cabut_manual(req: MitigasiRequest):
    """Mencabut pemblokiran alamat IP."""
    if not mitigator:
        raise HTTPException(503, "Modul mitigasi belum siap")

    berhasil = await _mitigasi(mitigator.cabut, req.ip)
    if not berhasil:
        raise HTTPException(500, f"Gagal mencabut blokir {req.ip}")

    _catat({
        "waktu": datetime.now().isoformat(),
        "jenis": "pencabutan_manual",
        "src_ip": req.ip,
        "keterangan": "Blokir dicabut manual",
    })
    await _siarkan_mitigasi("cabut", [req.ip], "manual")

    return {"status": "berhasil", "ip": req.ip}


def _ambil_menunggu(id_insiden):
    entri = antrean_persetujuan.get(id_insiden)
    if entri is None:
        ada = next((d for d in riwayat_deteksi if d.get("id") == id_insiden), None)
        if ada is None:
            raise HTTPException(404, f"Insiden {id_insiden} tidak ditemukan")
        raise HTTPException(409, f"Insiden {id_insiden} berstatus '{ada.get('status')}'")
    return entri


@app.post("/api/mitigasi/setujui/{id_insiden}")
async def setujui(id_insiden: int, durasi_menit: Optional[int] = None):
    """Menyetujui pemblokiran kandidat IP pada insiden yang menunggu persetujuan."""
    if not mitigator:
        raise HTTPException(503, "Modul mitigasi belum siap")
    entri = _ambil_menunggu(id_insiden)

    durasi = durasi_menit or cfg.DURASI_BLOKIR_MENIT
    diblokir = await _mitigasi(
        mitigator.blokir_banyak,
        entri["ip_kandidat"],
        durasi,
        f"disetujui admin: {entri['kelas']} {entri['kunci']}",
    )
    if not diblokir:
        raise HTTPException(500, f"Gagal memblokir {entri['ip_kandidat']}")

    t = _sekarang()
    entri.update({
        "status": "disetujui",
        "dimitigasi": True,
        "ip_blokir": diblokir,
        "t_mitigasi": _iso(t),
    })
    # Latensi mitigasi di sini mencakup waktu tunggu keputusan admin
    entri["latensi_detik"]["mitigasi"] = _selisih_detik(
        t, datetime.fromisoformat(entri["t_window_end"])
    )
    antrean_persetujuan.pop(id_insiden, None)
    await _siarkan_mitigasi("blokir", diblokir, "manual")
    await _siarkan_insiden(entri)
    return entri


@app.post("/api/mitigasi/tolak/{id_insiden}")
async def tolak(id_insiden: int):
    """Menolak pemblokiran; insiden tetap tercatat dengan status ditolak."""
    entri = _ambil_menunggu(id_insiden)
    entri["status"] = "ditolak"
    antrean_persetujuan.pop(id_insiden, None)
    # Penolakan tidak mengubah firewall, jadi cukup pembaruan insiden
    await _siarkan_insiden(entri)
    return entri


async def _snapshot():
    insiden = [d for d in riwayat_deteksi if d.get("jenis") == "insiden"]
    return {
        "tipe": "snapshot",
        "status": await status(),
        "insiden": insiden[:SNAPSHOT_INSIDEN],
        "terblokir": mitigator.daftar_terblokir() if mitigator else [],
        "trafik": list(trafik)[-SNAPSHOT_TRAFIK:],
    }


@app.websocket("/ws")
async def umpan_ws(ws: WebSocket):
    """
    Umpan real-time: satu pesan `snapshot` saat tersambung, lalu pesan
    `trafik` / `insiden` / `mitigasi` / `status` / `ping` dari siaran.
    Pesan dari klien diabaikan; loop baca hanya untuk mendeteksi putus.
    """
    await koneksi_ws.connect(ws, pesan_awal=_snapshot)
    try:
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        koneksi_ws.disconnect(ws)


@app.post("/api/setup-firewall")
async def setup_firewall():
    """Menyiapkan struktur firewall di router. Dijalankan sekali di awal."""
    if not mitigator:
        raise HTTPException(503, "Modul mitigasi belum siap")

    berhasil = await _mitigasi(mitigator.siapkan_firewall)
    return {"status": "berhasil" if berhasil else "gagal"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
