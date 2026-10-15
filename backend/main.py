"""
main.py
=======
Backend API untuk dashboard sistem NDR.

Menyatukan tiga komponen inti penelitian:
    1. Klasifikasi trafik menggunakan model machine learning terlatih
    2. Penyusunan narasi saran tindakan berbasis template
    3. Eksekusi mitigasi otomatis ke router melalui Netmiko

Menjalankan:
    uvicorn main:app --reload --host 0.0.0.0 --port 8000

Dokumentasi API otomatis tersedia di:
    http://localhost:8000/docs
"""

import asyncio
import sys
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# Menambahkan folder ml ke path agar modul penelitian dapat diimpor
sys.path.insert(0, str(Path(__file__).parent.parent / "ml"))

from mitigasi import ModulMitigasi          # noqa: E402
from saran_tindakan import susun_saran      # noqa: E402

# ------------------------------------------------------------- konfigurasi

ROUTER_HOST = "192.168.10.1"
ROUTER_USER = "vyos"
ROUTER_PASS = "vyos"

# Mode dry run mencegah perintah benar-benar dikirim ke router.
# Ubah menjadi False setelah pengujian di lingkungan simulasi selesai.
DRY_RUN = True

MODEL_PATH = Path(__file__).parent.parent / "model" / "model_terbaik.pkl"
LABEL_PATH = Path(__file__).parent.parent / "model" / "label_kelas.pkl"

FITUR = [
    "duration", "packet_count", "byte_count", "dst_port_count",
    "avg_packet_size", "flow_rate", "syn_flag_count",
    "unique_src_ip_per_dst", "protocol", "inter_arrival_time",
]

MAKS_RIWAYAT = 500

# --------------------------------------------------------------- aplikasi

app = FastAPI(
    title="Sistem Dashboard Keamanan Jaringan NDR",
    description="API deteksi dan mitigasi serangan siber pada jaringan kampus",
    version="1.0.0",
)

# CORS diperlukan agar frontend Next.js pada port berbeda dapat mengakses API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Penyimpanan sementara di memori. Untuk penggunaan jangka panjang,
# sebaiknya diganti dengan basis data.
riwayat_deteksi: List[dict] = []
model = None
label_kelas = None
mitigator: Optional[ModulMitigasi] = None


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


# ------------------------------------------------------------- siklus hidup


@app.on_event("startup")
async def startup():
    """Memuat model dan menyiapkan modul mitigasi saat server dinyalakan."""
    global model, label_kelas, mitigator

    try:
        import joblib
        model = joblib.load(MODEL_PATH)
        label_kelas = joblib.load(LABEL_PATH)
        print(f"Model dimuat: {MODEL_PATH.name}")
        print(f"Kelas: {label_kelas}")
    except Exception as e:
        print(f"PERINGATAN: model gagal dimuat ({e})")
        print("Endpoint /api/deteksi tidak akan berfungsi sampai model tersedia.")

    mitigator = ModulMitigasi(
        host=ROUTER_HOST,
        username=ROUTER_USER,
        password=ROUTER_PASS,
        dry_run=DRY_RUN,
    )
    print(f"Modul mitigasi siap (dry_run={DRY_RUN})")

    # Tugas latar belakang untuk mencabut blokir yang sudah kedaluwarsa
    asyncio.create_task(pencabut_berkala())


async def pencabut_berkala():
    """Memeriksa dan mencabut pemblokiran kedaluwarsa setiap satu menit."""
    while True:
        await asyncio.sleep(60)
        if mitigator:
            dicabut = mitigator.cabut_kedaluwarsa()
            for ip in dicabut:
                riwayat_deteksi.insert(0, {
                    "waktu": datetime.now().isoformat(),
                    "jenis": "pencabutan_otomatis",
                    "src_ip": ip,
                    "keterangan": "Blokir dicabut karena durasi berakhir",
                })


# --------------------------------------------------------------- endpoint


@app.get("/api/status")
async def status():
    """Status kesiapan sistem."""
    return {
        "model_dimuat": model is not None,
        "kelas": label_kelas,
        "router": ROUTER_HOST,
        "dry_run": DRY_RUN,
        "total_deteksi": len(riwayat_deteksi),
        "ip_terblokir": len(mitigator.terblokir) if mitigator else 0,
    }


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
    )

    entri = {
        "id": len(riwayat_deteksi) + 1,
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
    # dan tingkat kepercayaan melewati ambang yang ditetapkan
    if saran["mitigasi_otomatis"] and mitigator:
        berhasil = mitigator.blokir(
            flow.src_ip,
            durasi_menit=saran.get("durasi_blokir", 15),
            alasan=kelas,
        )
        entri["dimitigasi"] = berhasil

    riwayat_deteksi.insert(0, entri)
    del riwayat_deteksi[MAKS_RIWAYAT:]

    return entri


@app.get("/api/riwayat")
async def riwayat(limit: int = 50):
    """Riwayat deteksi terbaru."""
    return {"total": len(riwayat_deteksi), "data": riwayat_deteksi[:limit]}


@app.get("/api/ringkasan")
async def ringkasan():
    """Ringkasan statistik untuk ditampilkan pada dashboard."""
    deteksi_saja = [d for d in riwayat_deteksi if d.get("jenis") == "deteksi"]

    per_kelas = {}
    for d in deteksi_saja:
        k = d.get("kelas", "tidak diketahui")
        per_kelas[k] = per_kelas.get(k, 0) + 1

    return {
        "total_deteksi": len(deteksi_saja),
        "per_kelas": per_kelas,
        "total_mitigasi": sum(1 for d in deteksi_saja if d.get("dimitigasi")),
        "ip_terblokir": mitigator.daftar_terblokir() if mitigator else [],
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

    berhasil = mitigator.blokir(req.ip, req.durasi_menit, req.alasan)
    if not berhasil:
        raise HTTPException(500, f"Gagal memblokir {req.ip}")

    riwayat_deteksi.insert(0, {
        "waktu": datetime.now().isoformat(),
        "jenis": "mitigasi_manual",
        "src_ip": req.ip,
        "keterangan": f"Diblokir manual selama {req.durasi_menit} menit",
    })

    return {"status": "berhasil", "ip": req.ip}


@app.post("/api/mitigasi/cabut")
async def cabut_manual(req: MitigasiRequest):
    """Mencabut pemblokiran alamat IP."""
    if not mitigator:
        raise HTTPException(503, "Modul mitigasi belum siap")

    berhasil = mitigator.cabut(req.ip)
    if not berhasil:
        raise HTTPException(500, f"Gagal mencabut blokir {req.ip}")

    riwayat_deteksi.insert(0, {
        "waktu": datetime.now().isoformat(),
        "jenis": "pencabutan_manual",
        "src_ip": req.ip,
        "keterangan": "Blokir dicabut manual",
    })

    return {"status": "berhasil", "ip": req.ip}


@app.post("/api/setup-firewall")
async def setup_firewall():
    """Menyiapkan struktur firewall di router. Dijalankan sekali di awal."""
    if not mitigator:
        raise HTTPException(503, "Modul mitigasi belum siap")

    berhasil = mitigator.siapkan_firewall()
    return {"status": "berhasil" if berhasil else "gagal"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
