"""
konfigurasi.py
==============
Seluruh konfigurasi backend, dibaca dari environment / backend/.env
(lihat backend/.env.example). Nilai default adalah nilai aman untuk lab.

Dipisah dari main.py agar pipeline.py dan keputusan.py memakai konstanta
yang sama tanpa harus mengimpor aplikasi FastAPI.
"""

import os
from pathlib import Path

from dotenv import load_dotenv

DIR_BACKEND = Path(__file__).parent
DIR_REPO = DIR_BACKEND.parent

load_dotenv(DIR_BACKEND / ".env")


def _env_bool(nama, default):
    nilai = os.getenv(nama)
    if nilai is None:
        return default
    return nilai.strip().lower() in ("1", "true", "ya", "yes", "on")


def _env_list(nama, default):
    nilai = os.getenv(nama)
    if nilai is None:
        return list(default)
    return [x.strip() for x in nilai.split(",") if x.strip()]


def _env_path(nama, default):
    """Path relatif dianggap relatif terhadap root repo."""
    p = Path(os.getenv(nama, default))
    return p if p.is_absolute() else DIR_REPO / p


# ------------------------------------------------------------------ router

ROUTER_HOST = os.getenv("ROUTER_HOST", "192.168.42.198")
ROUTER_USER = os.getenv("ROUTER_USER", "vyos")
ROUTER_PASS = os.getenv("ROUTER_PASS", "vyos")

# Mode dry run mencegah perintah benar-benar dikirim ke router.
# Ubah menjadi false (DRY_RUN=false) setelah pengujian di lab selesai.
DRY_RUN = _env_bool("DRY_RUN", True)

DURASI_BLOKIR_MENIT = int(os.getenv("DURASI_BLOKIR_MENIT", "15"))

# ------------------------------------------------------- ambang & gerbang D3

# Ambang tingkat kepercayaan: >= TINGGI -> mitigasi otomatis,
# SEDANG..TINGGI -> menunggu persetujuan, < SEDANG -> hanya dicatat
AMBANG_TINGGI = float(os.getenv("AMBANG_TINGGI", "0.90"))
AMBANG_SEDANG = float(os.getenv("AMBANG_SEDANG", "0.50"))

# Insiden dengan flow serangan lebih sedikit dari ini diabaikan
MIN_FLOW_INSIDEN = int(os.getenv("MIN_FLOW_INSIDEN", "20"))
# Sumber hanya diblokir bila >= sekian bagian flow-nya berkelas serangan
AMBANG_RASIO_SERANGAN = float(os.getenv("AMBANG_RASIO_SERANGAN", "0.80"))
# Pemicu blokir otomatis per sumber: confidence rata-rata flow serangan
# sumber yang lolos gerbang rasio. AMBANG_SEDANG..ini -> menunggu
# persetujuan, di bawah AMBANG_SEDANG -> hanya dicatat.
AMBANG_CONF_BLOKIR = float(os.getenv("AMBANG_CONF_BLOKIR", "0.70"))

# Alamat yang tidak boleh diblokir otomatis: gateway VyOS tiap subnet,
# Collector, dan host backend (IP Windows dilihat dari VM GNS3)
ALLOWLIST = set(_env_list("ALLOWLIST", [
    "192.168.10.1", "192.168.20.1", "192.168.30.1", "192.168.100.1",
    "192.168.100.10",
    "192.168.172.1",
]))

# ------------------------------------------------------------------ pipeline

# Flow menuju subnet ini adalah backscatter (balasan Target ke alamat
# palsu hping3) dan dibuang sebelum klasifikasi, sama seperti saat pelabelan
SUBNET_BACKSCATTER = os.getenv("SUBNET_BACKSCATTER", "192.168.20.0/24")

# Bila true, packet_count seluruh flow diestimasi dari byte_count, sama
# seperti data latih. Bila false, field paket NetFlow dipakai apa adanya.
ESTIMASI_PAKET_PAKSA = _env_bool("ESTIMASI_PAKET_PAKSA", False)

MODEL_PATH = DIR_REPO / "ml" / "model" / "model_terbaik.pkl"

# ------------------------------------------------------------ sumber data

# "ingest" = menunggu POST /api/ingest (lab); "replay" = memutar ulang CSV
SUMBER = os.getenv("SUMBER", "ingest").strip().lower()
REPLAY_CSV = _env_path("REPLAY_CSV", "data/exp2/flows_sesi4.csv")
# Jeda antar jendela 60 detik saat replay (dipercepat untuk demo)
REPLAY_INTERVAL_DETIK = float(os.getenv("REPLAY_INTERVAL_DETIK", "3"))

# POST /api/ingest dengan {"path": ...} hanya boleh membaca file di sini
INGEST_DIR = _env_path("INGEST_DIR", "data")
