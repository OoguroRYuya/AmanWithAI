"""
analisis_revisi.py
==================
Analisis tambahan koreksi Pak Deni tahap 2 dari data yang SUDAH ADA (sesi 1-4).
Seluruh pemilihan dan analisis memakai data latih (sesi 1-2) dan validasi
(sesi 3). Data sesi 4 hanya dipakai untuk membandingkan distribusi (butir 9),
tidak untuk memilih apa pun.

Butir yang dijawab:
    9      distribusi kelas dan fitur sesi 1-4, uji KS sesi 3 vs sesi 4,
           porsi scan tanpa SYN (ACK/FIN scan) per sesi
    12     verifikasi rentang IP sumber generator dari data mentah
    17,18,66  permutation importance model final di VALIDASI, 10 ulangan,
           rata-rata dan simpangan baku, nilai negatif tetap ditampilkan
    19     ablation duration dan packet_count (XGBoost parameter bawaan,
           latih sesi 1-2, dinilai di validasi sesi 3)
    32     tabel alur jumlah data (mentah -> bersih -> backscatter -> ambigu
           -> berlabel -> pembagian)

Jalankan di GNS3 VM dari folder ml repo:
    cd ~/AmanWithAI/ml
    python3 analisis_revisi.py ~/eksperimen_fitur/dataset_gabungan.csv \
        --mentah F1 F2 F3 F4 --keluar ~/hasil_revisi
F1..F4 = CSV nfdump mentah sesi 1..4 (urut). --mentah boleh dilewati; bagian
butir 12 dan 32 versi mentah lalu tidak dijalankan.

Keluaran: ringkasan.txt (salinan layar) dan beberapa CSV di folder --keluar.
"""
import argparse
import os
import sys
import tempfile
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from scipy.stats import ks_2samp
from sklearn.ensemble import RandomForestClassifier
from sklearn.inspection import permutation_importance
from sklearn.metrics import f1_score
from xgboost import XGBClassifier

import ekstraksi_fitur as ef

FITUR = list(ef.FEATURE_COLUMNS)
KELAS = ["normal", "ddos_flood", "port_scanning"]
SESI_LATIH, SESI_VAL, SESI_UJI = [1, 2], [3], [4]
RANDOM_STATE = 42
N_ULANG = 10

# rentang generator (sama dengan label_per_window.py)
PREFIX_PENYERANG = "192.168.20."
RENTANG_SCAN = (11, 30)
RENTANG_FLOOD = (31, 250)


class Tee:
    def __init__(self, path):
        self.f = open(path, "w", encoding="utf-8")
        self.layar = sys.stdout

    def write(self, s):
        self.layar.write(s)
        self.f.write(s)

    def flush(self):
        self.layar.flush()
        self.f.flush()


def judul(teks):
    print(f"\n{'=' * 70}\n{teks}\n{'=' * 70}")


def f1m(y, p):
    return f1_score(y, p, average="macro")


# ------------------------------------------------------------------ butir 32/12
def bersihkan(path):
    """Simpan hanya baris data nfdump (10 kolom), seperti awk -F, 'NF==10'."""
    fd, tmp = tempfile.mkstemp(suffix=".csv", prefix="mentah_")
    n_in = n_out = 0
    with open(path, "r", errors="replace") as f, os.fdopen(fd, "w") as out:
        for baris in f:
            n_in += 1
            if baris.rstrip("\r\n").count(",") == 9:
                out.write(baris)
                if not baris.lstrip().startswith("ts"):  # header tidak dihitung
                    n_out += 1
    return tmp, n_in, n_out


def oktet(ip):
    return pd.to_numeric(ip.astype(str).str.rsplit(".", n=1).str[-1], errors="coerce")


def analisis_mentah(daftar, keluar):
    judul("Butir 32 dan 12: alur jumlah data dan rentang IP dari data mentah")
    alur, rentang = [], []
    for sesi, path in enumerate(daftar, start=1):
        tmp, n_in, n_bersih = bersihkan(path)
        try:
            df = ef.normalisasi_kolom(ef.baca_nfdump_csv(tmp))
        finally:
            os.remove(tmp)
        ts = pd.to_datetime(df["ts"], errors="coerce")
        df = df[ts.notna()].reset_index(drop=True)
        n_valid = len(df)
        sa, da = df["sa"].astype(str), df["da"].astype(str)
        bs = da.str.startswith(PREFIX_PENYERANG)
        sisa = df[~bs]
        s_sa = sisa["sa"].astype(str)
        okt = oktet(s_sa)
        penyerang = s_sa.str.startswith(PREFIX_PENYERANG)
        di_scan = penyerang & okt.between(*RENTANG_SCAN)
        di_flood = penyerang & okt.between(*RENTANG_FLOOD)
        ambigu = penyerang & ~di_scan & ~di_flood
        alur.append({
            "sesi": sesi, "baris_berkas": n_in, "baris_data": n_bersih,
            "flow_waktu_valid": n_valid, "backscatter_dibuang": int(bs.sum()),
            "di_luar_rentang_dibuang": int(ambigu.sum()),
            "normal": int((~penyerang).sum()), "port_scanning": int(di_scan.sum()),
            "ddos_flood": int(di_flood.sum()),
            "berlabel": int((~ambigu).sum()),
        })
        # butir 12: rentang IP sumber subnet penyerang (sebelum buang backscatter)
        semua_penyerang = sa[sa.str.startswith(PREFIX_PENYERANG)]
        o = oktet(semua_penyerang)
        for nama, lo, hi in (("gateway/host .1-.10", 1, 10), ("scanner .11-.30", *RENTANG_SCAN),
                             ("flooder .31-.250", *RENTANG_FLOOD), ("lain .251-.254", 251, 254)):
            m = o.between(lo, hi)
            rentang.append({"sesi": sesi, "rentang": nama, "flow": int(m.sum()),
                            "ip_unik": int(semua_penyerang[m].nunique()),
                            "oktet_min": None if not m.any() else int(o[m].min()),
                            "oktet_maks": None if not m.any() else int(o[m].max())})
        print(f"  sesi {sesi}: {path} selesai")
    a = pd.DataFrame(alur)
    r = pd.DataFrame(rentang)
    print("\nAlur jumlah data per sesi:")
    print(a.to_string(index=False))
    print("\nSumber subnet penyerang per rentang (semua flow, sebelum buang backscatter):")
    print(r.to_string(index=False))
    a.to_csv(keluar / "b32_alur_data_mentah.csv", index=False)
    r.to_csv(keluar / "b12_rentang_ip.csv", index=False)


# ------------------------------------------------------------------ butir 9
def analisis_distribusi(df, keluar):
    judul("Butir 9: distribusi kelas dan fitur per sesi")
    kelas = pd.crosstab(df["sesi"], df["label"], margins=True)
    print("Jumlah flow per sesi dan kelas:")
    print(kelas.to_string())
    porsi = pd.crosstab(df["sesi"], df["label"], normalize="index").round(4)
    print("\nProporsi kelas per sesi:")
    print(porsi.to_string())
    kelas.to_csv(keluar / "b9_kelas_per_sesi.csv")

    scan = df[df["label"] == "port_scanning"]
    tanpa_syn = (scan.assign(tanpa_syn=(scan["syn_flag_count"] == 0) & (scan["protocol"] == 6))
                 .groupby("sesi")["tanpa_syn"].agg(["sum", "count"]))
    tanpa_syn["porsi"] = (tanpa_syn["sum"] / tanpa_syn["count"]).round(4)
    print("\nFlow scan TCP tanpa SYN (ACK/FIN scan) per sesi:")
    print(tanpa_syn.to_string())
    tanpa_syn.to_csv(keluar / "b9_scan_tanpa_syn.csv")

    baris = []
    for kls in KELAS:
        for f in FITUR:
            for s in sorted(df["sesi"].unique()):
                x = df.loc[(df["sesi"] == s) & (df["label"] == kls), f]
                if x.empty:
                    continue
                baris.append({"kelas": kls, "fitur": f, "sesi": int(s), "n": len(x),
                              "rata": x.mean(), "median": x.median(), "p05": x.quantile(.05),
                              "p95": x.quantile(.95), "std": x.std()})
    stat = pd.DataFrame(baris)
    stat.to_csv(keluar / "b9_statistik_fitur.csv", index=False)

    ks = []
    for kls in KELAS:
        for f in FITUR:
            a = df.loc[(df["sesi"] == 3) & (df["label"] == kls), f]
            b = df.loc[(df["sesi"] == 4) & (df["label"] == kls), f]
            if a.empty or b.empty:
                continue
            r = ks_2samp(a, b)
            ks.append({"kelas": kls, "fitur": f, "median_s3": a.median(), "median_s4": b.median(),
                       "ks_D": round(r.statistic, 4), "p": r.pvalue})
    ks = pd.DataFrame(ks).sort_values("ks_D", ascending=False)
    print("\nUji Kolmogorov-Smirnov sesi 3 vs sesi 4 per kelas (D besar = distribusi berbeda):")
    print(ks.to_string(index=False, float_format=lambda v: f"{v:.4g}"))
    print("Catatan: dengan n puluhan ribu, p hampir selalu kecil; yang dibaca besarnya D.")
    ks.to_csv(keluar / "b9_ks_sesi3_vs_4.csv", index=False)


# ------------------------------------------------------------------ butir 17/18/66
def importance(nama, estimator, X, y, keluar):
    t = time.time()
    r = permutation_importance(estimator, X, y, scoring="f1_macro", n_repeats=N_ULANG,
                               random_state=RANDOM_STATE, n_jobs=1)
    tabel = pd.DataFrame({"fitur": FITUR, "rata": r.importances_mean,
                          "std": r.importances_std}).sort_values("rata", ascending=False)
    ulangan = pd.DataFrame(r.importances, index=FITUR,
                           columns=[f"ulang_{i + 1}" for i in range(N_ULANG)])
    print(f"\n{nama}: penurunan F1-makro validasi saat fitur diacak "
          f"({N_ULANG} ulangan, {time.time() - t:.0f} s)")
    print(tabel.to_string(index=False, float_format=lambda v: f"{v:.4f}"))
    neg = tabel[tabel["rata"] < 0]["fitur"].tolist()
    if neg:
        print(f"  Nilai negatif (mengacak fitur justru menaikkan F1 sedikit): {neg}")
    slug = nama.lower().replace(" ", "_")
    tabel.to_csv(keluar / f"b17_permutation_{slug}.csv", index=False)
    ulangan.to_csv(keluar / f"b17_permutation_{slug}_ulangan.csv")


def analisis_importance(latih, val, model_path, keluar):
    judul("Butir 17, 18, 66: permutation importance di data VALIDASI sesi 3")
    Xv, yv = val[FITUR], val["label"]
    m = joblib.load(model_path)
    nama_fitur = list(getattr(m, "feature_names_in_", FITUR))
    if nama_fitur != FITUR:
        sys.exit(f"Urutan fitur model {nama_fitur} beda dengan {FITUR}")
    peta = {v: k for k, v in m.balik.items()}
    print(f"Model final: {model_path} ({type(m.model).__name__})")
    print(f"F1-makro validasi model final: {f1m(yv, m.predict(Xv)):.4f} (naskah 0,9961)")
    importance("XGBoost final", m.model, Xv, yv.map(peta), keluar)

    rf = RandomForestClassifier(n_estimators=100, max_depth=None, min_samples_split=2,
                                random_state=RANDOM_STATE, n_jobs=-1, class_weight="balanced")
    rf.fit(latih[FITUR], latih["label"])
    print(f"\nRandom Forest dilatih ulang (parameter naskah), F1-makro validasi "
          f"{f1m(yv, rf.predict(Xv)):.4f} (naskah 0,9955)")
    importance("Random Forest", rf, Xv, yv, keluar)


# ------------------------------------------------------------------ butir 19
def analisis_ablation(latih, val, keluar):
    judul("Butir 19: ablation duration dan packet_count (XGBoost bawaan, nilai di validasi)")
    peta = {k: i for i, k in enumerate(sorted(latih["label"].unique()))}
    balik = {v: k for k, v in peta.items()}
    yl = latih["label"].map(peta)
    skenario = {
        "9 fitur (acuan)": [],
        "tanpa duration": ["duration"],
        "tanpa packet_count": ["packet_count"],
        "tanpa duration dan packet_count": ["duration", "packet_count"],
    }
    baris = []
    for nama, buang in skenario.items():
        f = [x for x in FITUR if x not in buang]
        m = XGBClassifier(n_estimators=100, max_depth=6, learning_rate=0.3,
                          random_state=RANDOM_STATE, n_jobs=-1, eval_metric="mlogloss")
        m.fit(latih[f], yl)
        p = pd.Series(m.predict(val[f])).map(balik).values
        per = f1_score(val["label"], p, average=None, labels=KELAS)
        baris.append({"skenario": nama, "jumlah_fitur": len(f), "f1_makro": f1m(val["label"], p),
                      **{f"f1_{k}": v for k, v in zip(KELAS, per)}})
        print(f"  {nama}: F1-makro {baris[-1]['f1_makro']:.4f}")
    t = pd.DataFrame(baris)
    print(t.to_string(index=False, float_format=lambda v: f"{v:.4f}"))
    t.to_csv(keluar / "b19_ablation.csv", index=False)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("dataset", help="dataset_gabungan.csv berlabel dengan kolom sesi")
    ap.add_argument("--mentah", nargs="*", default=[], help="CSV nfdump mentah sesi 1..4, urut")
    ap.add_argument("--model", default="model/model_terbaik.pkl")
    ap.add_argument("--keluar", default="hasil_revisi")
    ap.add_argument("--lewati", nargs="*", default=[],
                    help="bagian yang dilewati: mentah distribusi importance ablation")
    a = ap.parse_args()

    keluar = Path(a.keluar).expanduser()
    keluar.mkdir(parents=True, exist_ok=True)
    sys.stdout = Tee(keluar / "ringkasan.txt")
    print(f"analisis_revisi.py  {time.strftime('%Y-%m-%d %H:%M:%S')}")

    df = pd.read_csv(a.dataset)
    if "sesi" not in df.columns:
        sys.exit("Dataset tidak punya kolom 'sesi'")
    kurang = [f for f in FITUR if f not in df.columns]
    if kurang:
        sys.exit(f"Kolom fitur hilang: {kurang}")
    latih = df[df["sesi"].isin(SESI_LATIH)]
    val = df[df["sesi"].isin(SESI_VAL)]
    print(f"Dataset {a.dataset}: {len(df)} flow; latih {len(latih)}, validasi {len(val)}, "
          f"uji {len(df[df['sesi'].isin(SESI_UJI)])}")
    print("Butir 32 (dari dataset berlabel):")
    print(pd.crosstab(df["sesi"], df["label"], margins=True).to_string())

    if a.mentah and "mentah" not in a.lewati:
        analisis_mentah(a.mentah, keluar)
    if "distribusi" not in a.lewati:
        analisis_distribusi(df, keluar)
    if "importance" not in a.lewati:
        analisis_importance(latih, val, a.model, keluar)
    if "ablation" not in a.lewati:
        analisis_ablation(latih, val, keluar)
    print(f"\nSelesai. Semua keluaran di {keluar}")


if __name__ == "__main__":
    main()
