"""
pipeline.py
===========
Mengubah satu file CSV NetFlow (hasil nfdump) menjadi hasil per jendela 60
detik: jumlah trafik per kelas dan daftar insiden serangan yang sudah
dikelompokkan. Modul ini tidak bergantung pada FastAPI sehingga dapat diuji
tanpa server.

Alur proses_csv():
    1. ekstraksi 10 fitur (beserta sa/da/dp/window) dari CSV
    2. buang backscatter, yaitu flow menuju subnet penyerang. Fitur agregat
       sudah dihitung dari seluruh flow, lalu barisnya dibuang, persis seperti
       pada pelabelan data latih (label_per_window.py)
    3. predict_proba per flow; kelas = probabilitas tertinggi, confidence =
       nilai probabilitas tersebut
    4. kelompokkan per jendela: trafik per kelas, per sumber, dan insiden

Insiden dikelompokkan berdasarkan kunci:
    port_scanning -> IP sumber (pemindai)
    ddos_flood    -> IP tujuan (korban), karena sumber flood dipalsukan
Flow normal tidak membentuk insiden; hanya masuk hitungan trafik.
"""

import ipaddress
import sys
from dataclasses import dataclass, field
from typing import Dict, List

import pandas as pd

import konfigurasi as cfg

sys.path.insert(0, str(cfg.DIR_REPO / "ml"))

import ekstraksi_fitur as ef  # noqa: E402

KELAS = ("normal", "ddos_flood", "port_scanning")
KELAS_SERANGAN = ("ddos_flood", "port_scanning")

# Kolom yang menjadi kunci insiden untuk tiap kelas serangan
KUNCI_INSIDEN = {"port_scanning": "sa", "ddos_flood": "da"}


@dataclass
class Insiden:
    window: str
    kelas: str
    kunci: str
    jumlah_flow: int
    sumber: List[str]
    tujuan: List[str]
    confidence: float
    packet_total: int
    byte_total: int
    dst_port_maks: int


@dataclass
class HasilWindow:
    window: str
    window_epoch: int
    per_kelas: Dict[str, int]
    byte_total: int
    jumlah_backscatter: int
    insiden: List[Insiden] = field(default_factory=list)
    # {sa: {"normal": n, "ddos_flood": n, "port_scanning": n,
    #       "total": n, "serangan": n, "conf_serangan": jumlah confidence}}
    per_sumber: Dict[str, dict] = field(default_factory=dict)


def label_window(window_idx):
    """Indeks jendela -> waktu awal jendela (ISO, zona waktu data)."""
    return pd.Timestamp(int(window_idx) * ef.WINDOW_SECONDS, unit="s").isoformat()


def akhir_window(window_epoch):
    """Waktu akhir jendela (dari detik awal jendela) sebagai Timestamp naif."""
    return pd.Timestamp(int(window_epoch) + ef.WINDOW_SECONDS, unit="s")


def potong_per_window(path):
    """
    Memotong satu CSV nfdump menjadi potongan per jendela WINDOW_SECONDS
    berdasarkan kolom waktu pertama (`ts`). Dipakai mode replay.

    Batas jendela dihitung dengan rumus yang sama seperti ekstraksi fitur,
    sehingga fitur agregat tiap potongan identik dengan ekstraksi satu file
    utuh. Mengembalikan list (window_idx, bytes CSV berheader).
    """
    with open(path, "r", errors="replace") as f:
        baris = f.read().splitlines(keepends=True)
    if not baris:
        return []

    if ef._punya_header(path):
        header, data = baris[0], baris[1:]
    else:
        header, data = ",".join(ef.KOLOM_FMT_DEFAULT) + "\n", baris

    ts = pd.to_datetime(
        pd.Series([b.split(",", 1)[0].strip() for b in data]), errors="coerce"
    )
    window = (ts - pd.Timestamp("1970-01-01")) // pd.Timedelta(seconds=ef.WINDOW_SECONDS)

    potongan = {}
    for b, w in zip(data, window):
        if pd.isna(w):
            continue
        potongan.setdefault(int(w), []).append(b)

    return [
        (w, (header + "".join(isi)).encode())
        for w, isi in sorted(potongan.items())
    ]


def tandai_backscatter(da, subnet=cfg.SUBNET_BACKSCATTER):
    """Series boolean: True bila alamat tujuan berada di subnet backscatter."""
    jaringan = ipaddress.ip_network(subnet)

    def di_subnet(ip):
        try:
            return ipaddress.ip_address(ip) in jaringan
        except ValueError:
            return False

    peta = {ip: di_subnet(ip) for ip in da.unique()}
    return da.map(peta).astype(bool)


def prediksi(df, model):
    """Menambahkan kolom `kelas` dan `confidence` ke df (salinan)."""
    df = df.copy()
    if df.empty:
        df["kelas"] = pd.Series(dtype=str)
        df["confidence"] = pd.Series(dtype=float)
        return df
    proba = model.predict_proba(df[ef.FEATURE_COLUMNS])
    # Untuk Random Forest, argmax predict_proba identik dengan predict()
    df["kelas"] = model.classes_[proba.argmax(axis=1)].astype(str)
    df["confidence"] = proba.max(axis=1)
    return df


def _per_sumber(grup):
    hasil = {}
    for sa, g in grup.groupby("sa"):
        hitung = g["kelas"].value_counts()
        serangan = g[g["kelas"].isin(KELAS_SERANGAN)]
        entri = {k: int(hitung.get(k, 0)) for k in KELAS}
        entri["total"] = int(len(g))
        entri["serangan"] = int(len(serangan))
        entri["conf_serangan"] = float(serangan["confidence"].sum())
        hasil[str(sa)] = entri
    return hasil


def _insiden(grup, label):
    hasil = []
    for kelas, kolom_kunci in KUNCI_INSIDEN.items():
        serangan = grup[grup["kelas"] == kelas]
        for kunci, g in serangan.groupby(kolom_kunci):
            hasil.append(Insiden(
                window=label,
                kelas=kelas,
                kunci=str(kunci),
                jumlah_flow=int(len(g)),
                sumber=sorted(g["sa"].astype(str).unique().tolist()),
                tujuan=sorted(g["da"].astype(str).unique().tolist()),
                confidence=float(g["confidence"].mean()),
                packet_total=int(g["packet_count"].sum()),
                byte_total=int(g["byte_count"].sum()),
                dst_port_maks=int(g["dst_port_count"].max()),
            ))
    return hasil


def kelompokkan(df, backscatter_per_window=None):
    """
    Mengelompokkan flow yang sudah diprediksi menjadi HasilWindow.

    df harus memiliki kolom fitur, `sa`, `da`, `window`, `kelas`, dan
    `confidence`. backscatter_per_window: {window: jumlah flow dibuang},
    dipakai agar jendela yang seluruhnya backscatter tetap muncul.
    """
    backscatter_per_window = backscatter_per_window or {}
    semua_window = sorted(set(df["window"].unique()) | set(backscatter_per_window))

    hasil = []
    for w in semua_window:
        grup = df[df["window"] == w]
        label = label_window(w)
        hitung = grup["kelas"].value_counts()
        hasil.append(HasilWindow(
            window=label,
            window_epoch=int(w) * ef.WINDOW_SECONDS,
            per_kelas={k: int(hitung.get(k, 0)) for k in KELAS},
            byte_total=int(grup["byte_count"].sum()),
            jumlah_backscatter=int(backscatter_per_window.get(w, 0)),
            insiden=_insiden(grup, label),
            per_sumber=_per_sumber(grup),
        ))
    return hasil


def proses_csv(path, model, estimasi_paksa=None):
    """
    Memproses satu file CSV nfdump. Mengembalikan list HasilWindow, satu per
    jendela 60 detik yang ada di file (file nfcapd dapat memuat flow dari
    lebih dari satu jendela karena flow diekspor setelah selesai/timeout).
    """
    if estimasi_paksa is None:
        estimasi_paksa = cfg.ESTIMASI_PAKET_PAKSA

    df = ef.ekstrak(path, sertakan_ip=True, estimasi_paksa=estimasi_paksa)

    backscatter = tandai_backscatter(df["da"])
    backscatter_per_window = df.loc[backscatter, "window"].value_counts().to_dict()
    df = df[~backscatter].reset_index(drop=True)

    df = prediksi(df, model)
    return kelompokkan(df, backscatter_per_window)
