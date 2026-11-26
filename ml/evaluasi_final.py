"""Evaluasi SATU KALI model yang dibekukan pada sesi uji final baru (sesi 6).

Pengganti evaluasi_sesi5.py setelah perbaikan 10 fitur (26 Nov 2026). Sesi 4
dan 5 sekarang menjadi data evaluasi pengembangan; sesi 6 direkam setelah
model, ambang, kode, dan KRITERIA dibekukan.

Alur (semuanya dari berkas mentah supaya pelabelan identik dengan sesi 1-5):
  1. Baca CSV flow nfdump sesi uji, buang backscatter, label dari rentang IP
     (sama dengan label_per_window.py --metode rentang).
  2. Model final (model/model_terbaik.pkl) dan model pembanding (algoritma
     lainnya, dilatih ulang pada sesi 1-2 dengan parameter naskah) dinilai.
  3. Recall scan per jenis nmap dari log generator.
  4. Kriteria dari kriteria_sesi6.json (dibekukan SEBELUM perekaman) dicek
     otomatis dan dilaporkan LULUS/TIDAK apa adanya.
Bila folder keluaran sudah berisi hasil, skrip menolak jalan lagi.

Jalankan di GNS3 VM (folder ml):
    python3 evaluasi_final.py --sesi 6 ~/dataset_retrain/bersih_sesi6.csv \
        ~/dataset_retrain/scan_sesi6.log \
        --latih ~/eksperimen_10fitur/dataset_gabungan.csv \
        --kriteria kriteria_sesi6.json --keluar ~/hasil_sesi6
"""
import argparse
import hashlib
import json
import sys
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import (accuracy_score, classification_report, confusion_matrix,
                             f1_score, precision_score, recall_score)

import banding_sesi as b
import ekstraksi_fitur as ef

FITUR = list(ef.FEATURE_COLUMNS)
KELAS = ["ddos_flood", "normal", "port_scanning"]


def nilai(nama, y, p):
    cm = confusion_matrix(y, p, labels=KELAS)
    total = cm.sum()
    per = {}
    for i, k in enumerate(KELAS):
        tp = cm[i, i]
        fn = cm[i].sum() - tp
        fp = cm[:, i].sum() - tp
        tn = total - tp - fn - fp
        per[k] = {"FPR": float(fp / (fp + tn)) if fp + tn else 0.0,
                  "FNR": float(fn / (fn + tp)) if fn + tp else 0.0}
    h = {
        "model": nama,
        "accuracy": accuracy_score(y, p),
        "precision_makro": precision_score(y, p, average="macro", labels=KELAS, zero_division=0),
        "recall_makro": recall_score(y, p, average="macro", labels=KELAS, zero_division=0),
        "f1_makro": f1_score(y, p, average="macro", labels=KELAS, zero_division=0),
        "per_kelas": classification_report(y, p, labels=KELAS, output_dict=True, zero_division=0),
        "fpr_fnr": per,
        "confusion_matrix": {"baris_aktual_kolom_prediksi": KELAS, "nilai": cm.tolist()},
    }
    print(f"\n== {nama}")
    print(f"Accuracy {h['accuracy']:.4f}  Precision {h['precision_makro']:.4f}  "
          f"Recall {h['recall_makro']:.4f}  F1-makro {h['f1_makro']:.4f}")
    print(classification_report(y, p, labels=KELAS, digits=4, zero_division=0))
    print("Confusion matrix (baris aktual, kolom prediksi", KELAS, "):")
    print(pd.DataFrame(cm, index=KELAS, columns=KELAS).to_string())
    print("FPR/FNR:", {k: {m: round(v, 4) for m, v in d.items()} for k, d in per.items()})
    return h


def pembanding(final, latih):
    """Algoritma yang TIDAK terpilih, dilatih ulang di sesi 1-2 (parameter naskah)."""
    if type(final).__name__ == "XGBWrapper":
        from sklearn.ensemble import RandomForestClassifier
        m = RandomForestClassifier(n_estimators=100, max_depth=None, min_samples_split=2,
                                   random_state=42, n_jobs=-1, class_weight="balanced")
        return "Random Forest (pembanding)", m.fit(latih[FITUR], latih["label"])
    from xgboost import XGBClassifier
    from model_wrapper import XGBWrapper
    kelas = sorted(latih["label"].unique().tolist())
    peta = {k: i for i, k in enumerate(kelas)}
    m = XGBClassifier(n_estimators=100, max_depth=6, learning_rate=0.3, random_state=42,
                      n_jobs=-1, eval_metric="mlogloss")
    m.fit(latih[FITUR], latih["label"].map(peta))
    return "XGBoost (pembanding)", XGBWrapper(m, peta, FITUR)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--sesi", type=int, required=True)
    ap.add_argument("flow", help="CSV flow nfdump sesi uji (mentah atau bersih)")
    ap.add_argument("log_scan", help="log serang_scan.sh sesi uji")
    ap.add_argument("--latih", required=True, help="dataset_gabungan.csv 10 fitur (sesi 1-2 untuk pembanding)")
    ap.add_argument("--kriteria", required=True, help="kriteria_sesi6.json yang dibekukan")
    ap.add_argument("--model", default="model/model_terbaik.pkl")
    ap.add_argument("--keluar", default="hasil_sesi6")
    a = ap.parse_args()

    keluar = Path(a.keluar).expanduser()
    berkas = keluar / f"evaluasi_sesi{a.sesi}.json"
    if berkas.exists():
        sys.exit(f"{berkas} sudah ada. Evaluasi uji final hanya sekali; hasil itu yang dilaporkan.")
    keluar.mkdir(parents=True, exist_ok=True)

    kriteria_teks = Path(a.kriteria).read_bytes()
    kriteria = json.loads(kriteria_teks)
    kosong = [k for k, v in kriteria.items() if v is None]
    if kosong:
        sys.exit(f"Kriteria belum lengkap: {kosong}. Isi dan bekukan sebelum merekam sesi uji.")
    sha_model = hashlib.sha256(Path(a.model).read_bytes()).hexdigest()
    sha_krit = hashlib.sha256(kriteria_teks).hexdigest()
    print(f"Model {a.model} sha256 {sha_model}")
    print(f"Kriteria {a.kriteria} sha256 {sha_krit}")

    df = b.baca_flow(a.flow)
    y = df["label"]
    print(f"Sesi {a.sesi}: {len(df)} flow; {y.value_counts().to_dict()}")
    final = joblib.load(a.model)
    p_final = np.asarray(final.predict(df[FITUR])).astype(str)
    nama_final = ("XGBoost (final)" if type(final).__name__ == "XGBWrapper"
                  else "Random Forest (final)")
    hasil = {"waktu": time.strftime("%Y-%m-%d %H:%M:%S"), "sesi": a.sesi, "berkas_flow": a.flow,
             "jumlah_flow": len(df), "per_kelas_aktual": y.value_counts().to_dict(),
             "model_sha256": sha_model, "kriteria_sha256": sha_krit, "kriteria": kriteria,
             "hasil": [nilai(nama_final, y, p_final)]}

    g = pd.read_csv(Path(a.latih).expanduser())
    nama_p, mp = pembanding(final, g[g["sesi"].isin([1, 2])])
    hasil["hasil"].append(nilai(nama_p, y, np.asarray(mp.predict(df[FITUR])).astype(str)))

    # recall scan per jenis nmap (model final)
    log = b.baca_log(a.log_scan)
    scan = df[y == "port_scanning"].copy()
    geser, frac = b.cari_geser(scan, log)
    scan["run"] = b.kaitkan(scan, log, geser)
    scan["pred"] = p_final[(y == "port_scanning").to_numpy()]
    scan = scan.merge(log[["run", "jenis"]], on="run", how="left")
    scan["jenis"] = scan["jenis"].fillna("tidak terkait log")
    per_jenis = scan.groupby("jenis").agg(flow=("pred", "size"),
                                          recall=("pred", lambda s: (s == "port_scanning").mean()))
    print(f"\n== Recall scan per jenis nmap (model final); flow terkait log {frac:.1%}")
    print(per_jenis.round(4).to_string())
    hasil["recall_per_jenis"] = per_jenis.round(4).to_dict(orient="index")
    hasil["log_scan"] = {"perintah": len(log), "per_jenis": log["jenis"].value_counts().to_dict(),
                         "flow_terkait": round(frac, 4)}

    # cek kriteria (otomatis, apa adanya)
    f1 = hasil["hasil"][0]["f1_makro"]
    cek = {}
    k = kriteria["K1_f1_makro_min"]
    cek["K1"] = {"syarat": f"F1 makro final >= {k}", "nilai": round(f1, 4), "lulus": f1 >= k}
    dev, d = kriteria["K2_f1_pengembangan"], kriteria["K2_selisih_maks"]
    cek["K2"] = {"syarat": f"|F1 final - {dev}| <= {d}", "nilai": round(abs(f1 - dev), 4),
                 "lulus": abs(f1 - dev) <= d}
    rmin, fmin = kriteria["K3_recall_jenis_min"], kriteria["K3_flow_min_per_jenis"]
    besar = per_jenis[(per_jenis["flow"] >= fmin) & (per_jenis.index != "tidak terkait log")]
    cek["K3"] = {"syarat": f"recall scan tiap jenis nmap (>= {fmin} flow) >= {rmin}",
                 "nilai": besar["recall"].round(4).to_dict(),
                 "lulus": bool((besar["recall"] >= rmin).all())}
    cek["K4"] = {"syarat": kriteria.get("K4_insiden", ""), "nilai": "dicek dengan replay_tally.py di PC B",
                 "lulus": None}
    hasil["cek_kriteria"] = cek
    print("\n== Kriteria (dibekukan sebelum perekaman)")
    for kode, c in cek.items():
        status = "-" if c["lulus"] is None else ("LULUS" if c["lulus"] else "TIDAK LULUS")
        print(f"{kode}: {c['syarat']}; nilai {c['nilai']}; {status}")

    berkas.write_text(json.dumps(hasil, indent=1, default=float), encoding="utf-8")
    print(f"\nTersimpan: {berkas}. Jangan ubah model, ambang, kriteria, atau kode setelah melihat angka ini.")


if __name__ == "__main__":
    main()
