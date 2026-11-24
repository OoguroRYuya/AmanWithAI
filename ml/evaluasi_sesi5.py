"""Evaluasi SATU KALI model yang dibekukan pada data uji final sesi 5.

Model final (model/model_terbaik.pkl, XGBoost 9 fitur, dilatih sesi 1-2) dan
Random Forest pembanding (parameter naskah, dilatih ulang pada sesi 1-2 dengan
random_state tetap) dinilai pada sesi 5. Tidak ada yang dipilih atau diubah
dari hasil ini. Bila folder keluaran sudah berisi hasil, skrip menolak jalan
lagi supaya evaluasi benar-benar hanya sekali.

Jalankan di GNS3 VM:
    cd ~/AmanWithAI/ml
    python3 evaluasi_sesi5.py ~/eksperimen_fitur/dataset_sesi5.csv \
        --latih ~/eksperimen_fitur/dataset_gabungan.csv --keluar ~/hasil_sesi5
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
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (accuracy_score, classification_report, confusion_matrix,
                             f1_score, precision_score, recall_score)

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


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("uji", help="dataset_sesi5.csv berlabel (label_per_window --metode rentang)")
    ap.add_argument("--latih", required=True, help="dataset_gabungan.csv (sesi 1-2 dipakai melatih RF)")
    ap.add_argument("--model", default="model/model_terbaik.pkl")
    ap.add_argument("--keluar", default="hasil_sesi5")
    a = ap.parse_args()

    keluar = Path(a.keluar).expanduser()
    berkas = keluar / "evaluasi_sesi5.json"
    if berkas.exists():
        sys.exit(f"{berkas} sudah ada. Evaluasi sesi 5 hanya dilakukan sekali; hasil itu yang dilaporkan.")
    keluar.mkdir(parents=True, exist_ok=True)

    uji = pd.read_csv(a.uji)
    print(f"Sesi 5: {len(uji)} flow; {uji['label'].value_counts().to_dict()}")
    X, y = uji[FITUR], uji["label"]
    sha = hashlib.sha256(Path(a.model).read_bytes()).hexdigest()
    print(f"Model {a.model} sha256 {sha}")

    m = joblib.load(a.model)
    p_xgb = m.predict(X)
    hasil = {"waktu": time.strftime("%Y-%m-%d %H:%M:%S"), "berkas_uji": a.uji,
             "jumlah_flow": len(uji), "per_kelas_aktual": y.value_counts().to_dict(),
             "model_sha256": sha, "hasil": [nilai("XGBoost (final)", y, p_xgb)]}

    df = pd.read_csv(a.latih)
    latih = df[df["sesi"].isin([1, 2])]
    rf = RandomForestClassifier(n_estimators=100, max_depth=None, min_samples_split=2,
                                random_state=42, n_jobs=-1, class_weight="balanced")
    rf.fit(latih[FITUR], latih["label"])
    hasil["hasil"].append(nilai("Random Forest (pembanding)", y, rf.predict(X)))

    proba = m.predict_proba(X)
    pred = pd.DataFrame({"label": y, "pred": p_xgb, "conf": proba.max(1)})
    for k in ("sa", "da", "ts_epoch"):
        if k in uji.columns:
            pred[k] = uji[k]
    pred.to_csv(keluar / "prediksi_xgb_sesi5.csv", index=False)
    berkas.write_text(json.dumps(hasil, indent=1, default=float), encoding="utf-8")
    print(f"\nTersimpan: {berkas}. Jangan ubah model, ambang, atau kode setelah melihat angka ini.")


if __name__ == "__main__":
    main()
