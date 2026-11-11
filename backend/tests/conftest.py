import os
import sys
import tempfile
from pathlib import Path

import pandas as pd
import pytest

DIR_TES = Path(__file__).parent
DIR_BACKEND = DIR_TES.parent
DIR_REPO = DIR_BACKEND.parent

sys.path.insert(0, str(DIR_BACKEND))
sys.path.insert(0, str(DIR_REPO / "ml"))

import keamanan as km  # noqa: E402

PASSWORD_UJI = "password-uji-ndr-12345"
TOKEN_UJI = "token-ingest-uji"

# Dipasang SEBELUM konfigurasi diimpor (load_dotenv tidak menimpa env yang
# sudah ada), supaya pengujian tidak pernah mengirim perintah ke router
# meski backend/.env berisi DRY_RUN=false
os.environ["DRY_RUN"] = "true"
os.environ["SUMBER"] = "ingest"
os.environ["ADMIN_PASSWORD_HASH"] = km.buat_hash(PASSWORD_UJI)
os.environ["INGEST_TOKEN"] = TOKEN_UJI
# TestClient memakai host peer "testclient"
os.environ["ADMIN_SUMBER"] = "127.0.0.1,::1,testclient"
os.environ["INGEST_SUMBER"] = "127.0.0.1,::1,testclient"
# Status blokir tiap sesi uji di folder sementara, tidak bocor antar sesi
os.environ["DIR_STATUS"] = tempfile.mkdtemp(prefix="ndr_status_uji_")

import ekstraksi_fitur as ef  # noqa: E402

FIXTURE_CSV = DIR_TES / "data" / "potongan_sesi4_0942.csv"
FIXTURE_GOLDEN = DIR_TES / "data" / "potongan_sesi4_0942_fitur_golden.csv"
MODEL_PATH = DIR_REPO / "ml" / "model" / "model_terbaik.pkl"
SESI4_CSV = DIR_REPO / "data" / "exp2" / "flows_sesi4.csv"


def flow(sa, da, kelas, confidence=0.95, window=0, dp=80, **fitur):
    """Satu baris flow yang sudah diprediksi, untuk menyusun kasus uji."""
    baris = {c: 0 for c in ef.FEATURE_COLUMNS}
    baris.update(packet_count=2, byte_count=88, dst_port_count=1, protocol=6)
    baris.update(fitur)
    baris.update(sa=sa, da=da, dp=dp, window=window, kelas=kelas, confidence=confidence)
    return baris


def bingkai(baris):
    return pd.DataFrame(baris)


def model_cocok():
    """True bila model ada DAN dilatih dengan fitur ekstraktor sekarang."""
    if not MODEL_PATH.exists():
        return False
    import joblib
    return list(getattr(joblib.load(MODEL_PATH), "feature_names_in_", [])) == ef.FEATURE_COLUMNS


ALASAN_MODEL = "model tidak ada atau belum dilatih ulang dengan fitur ekstraktor sekarang"


@pytest.fixture(scope="session")
def model():
    if not model_cocok():
        pytest.skip(ALASAN_MODEL)
    import joblib
    return joblib.load(MODEL_PATH)


@pytest.fixture(scope="session")
def klien():
    from fastapi.testclient import TestClient
    import main
    # Satu TestClient untuk seluruh sesi uji (test_api dan test_ws):
    # antrean asyncio terikat ke event loop pertama yang memakainya.
    # Token ingest dipasang sebagai header bawaan; sesi admin lewat login.
    with TestClient(main.app, headers={"Authorization": f"Bearer {TOKEN_UJI}"}) as c:
        r = c.post("/api/masuk", json={"password": PASSWORD_UJI})
        assert r.status_code == 200, r.text
        yield c
