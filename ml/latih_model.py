"""
latih_model.py
==============
Melatih dan membandingkan dua algoritma klasifikasi (Random Forest dan
XGBoost) untuk mendeteksi serangan berdasarkan fitur NetFlow, sesuai
rancangan pada BAB III proposal.

Alur pemakaian:
    1. Gabungkan dataset hasil ekstraksi tiap kelas:
         python latih_model.py --gabung dataset_normal.csv dataset_ddos.csv \
                dataset_portscan.csv -o dataset_gabungan.csv
    2. Latih dan evaluasi kedua model:
         python latih_model.py dataset_gabungan.csv

Keluaran:
    - Metrik evaluasi (accuracy, precision, recall, F1-score) kedua model
    - Confusion matrix kedua model
    - Analisis feature importance
    - Model terbaik tersimpan sebagai model_terbaik.pkl
"""

import argparse
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import GroupShuffleSplit, train_test_split

FITUR = [
    "duration",
    "packet_count",
    "byte_count",
    "dst_port_count",
    "avg_packet_size",
    "flow_rate",
    "syn_flag_count",
    "unique_src_ip_per_dst",
    "protocol",
    "inter_arrival_time",
]

KELAS = ["normal", "ddos_flood", "port_scanning"]

RANDOM_STATE = 42
TEST_SIZE = 0.3


# ---------------------------------------------------------------- utilitas


def gabung_dataset(daftar_file, output):
    """Menggabungkan beberapa file dataset berlabel menjadi satu."""
    bagian = []
    for i, f in enumerate(daftar_file, start=1):
        df = pd.read_csv(f)
        if "label" not in df.columns:
            raise ValueError(f"{f} tidak memiliki kolom 'label'")
        # Beri penanda sesi bila file belum punya kolom 'sesi'. Satu file =
        # satu sesi pengumpulan. Penanda ini dipakai saat pelatihan untuk
        # memisahkan data latih dan uji per sesi, supaya flow dari serangan
        # yang sama tidak bocor ke kedua sisi (membesarkan skor secara semu).
        if "sesi" not in df.columns:
            df["sesi"] = i
        bagian.append(df)
        print(
            f"  {f}: {len(df)} record, label {df['label'].unique().tolist()}, "
            f"sesi {sorted(df['sesi'].unique().tolist())}"
        )

    gabungan = pd.concat(bagian, ignore_index=True)
    gabungan = gabungan.sample(frac=1, random_state=RANDOM_STATE).reset_index(drop=True)
    gabungan.to_csv(output, index=False)

    print(f"\nTotal {len(gabungan)} record tersimpan di {output}")
    print("\nDistribusi kelas:")
    print(gabungan["label"].value_counts().to_string())
    return gabungan


def periksa_dataset(df):
    """
    Memeriksa kualitas dataset sebelum pelatihan.

    Pemeriksaan ini penting karena masalah pada data jauh lebih sering
    menjadi penyebab performa model yang buruk dibanding pemilihan algoritma.
    """
    masalah = []

    kurang = [f for f in FITUR if f not in df.columns]
    if kurang:
        masalah.append(f"Kolom fitur tidak lengkap: {kurang}")

    if "label" not in df.columns:
        masalah.append("Kolom 'label' tidak ditemukan")

    if masalah:
        for m in masalah:
            print(f"  [GAGAL] {m}")
        return False

    print(f"  Jumlah record   : {len(df)}")
    print(f"  Jumlah fitur    : {len(FITUR)}")
    print(f"  Jumlah kelas    : {df['label'].nunique()}")

    # Fitur konstan tidak memberi informasi apa pun bagi model
    konstan = [f for f in FITUR if df[f].nunique() <= 1]
    if konstan:
        print(f"  [PERINGATAN] Fitur bernilai konstan: {konstan}")
        print("               Periksa apakah exporter NetFlow mengirim field ini.")

    # Ketidakseimbangan kelas yang ekstrem membuat accuracy menyesatkan
    dist = df["label"].value_counts()
    rasio = dist.max() / dist.min() if dist.min() > 0 else float("inf")
    print(f"  Rasio kelas     : {rasio:.1f} : 1")
    if rasio > 10:
        print("  [PERINGATAN] Distribusi kelas sangat timpang.")
        print("               Perhatikan precision dan recall, bukan accuracy.")

    return True


# ---------------------------------------------------------------- evaluasi


def evaluasi(nama, model, X_test, y_test, label_kelas):
    """Menghitung seluruh metrik evaluasi untuk satu model."""
    y_pred = model.predict(X_test)

    hasil = {
        "nama": nama,
        "accuracy": accuracy_score(y_test, y_pred),
        "precision_macro": precision_score(y_test, y_pred, average="macro", zero_division=0),
        "recall_macro": recall_score(y_test, y_pred, average="macro", zero_division=0),
        "f1_macro": f1_score(y_test, y_pred, average="macro", zero_division=0),
        "confusion_matrix": confusion_matrix(y_test, y_pred).tolist(),
        "laporan": classification_report(
            y_test, y_pred, target_names=label_kelas, zero_division=0, output_dict=True
        ),
    }

    print(f"\n{'=' * 58}")
    print(f"  {nama}")
    print(f"{'=' * 58}")
    print(f"  Accuracy          : {hasil['accuracy']:.4f}")
    print(f"  Precision (macro) : {hasil['precision_macro']:.4f}")
    print(f"  Recall    (macro) : {hasil['recall_macro']:.4f}")
    print(f"  F1-score  (macro) : {hasil['f1_macro']:.4f}")

    print("\n  Confusion Matrix")
    print("  (baris = aktual, kolom = prediksi)")
    cm = np.array(hasil["confusion_matrix"])
    lebar = max(len(k) for k in label_kelas) + 2
    print(" " * (lebar + 2) + "".join(f"{k[:10]:>12}" for k in label_kelas))
    for i, k in enumerate(label_kelas):
        baris = "".join(f"{v:>12}" for v in cm[i])
        print(f"  {k:<{lebar}}{baris}")

    print("\n  Rincian per kelas")
    print(classification_report(y_test, y_pred, target_names=label_kelas, zero_division=0))

    return hasil


def tampilkan_feature_importance(model, nama):
    """
    Menampilkan kontribusi tiap fitur terhadap keputusan model.

    Analisis ini berguna untuk memvalidasi pemilihan sepuluh fitur secara
    empiris, dan dapat dilampirkan pada pembahasan hasil penelitian.
    """
    if not hasattr(model, "feature_importances_"):
        return None

    imp = pd.Series(model.feature_importances_, index=FITUR).sort_values(ascending=False)

    print(f"\n  Feature importance ({nama})")
    for fitur, nilai in imp.items():
        bar = "#" * int(nilai * 50)
        print(f"    {fitur:<24} {nilai:.4f}  {bar}")

    return imp.to_dict()


# ---------------------------------------------------------------- pelatihan


def latih(df, simpan_model=True, uji_sesi=None):
    """Melatih kedua model, mengevaluasi, lalu memilih yang terbaik.

    Pemisahan data latih/uji:
    - Bila ada kolom 'sesi', pemisahan dilakukan PER SESI, bukan per flow:
      seluruh flow dari satu sesi masuk ke salah satu sisi saja. Ini penting
      karena flow dari satu serangan yang sama (satu sesi) sangat mirip; bila
      sebagian masuk latih dan sebagian masuk uji, model seolah "sudah pernah
      melihat" data uji sehingga skornya naik secara semu (kebocoran data).
    - Bila tidak ada kolom 'sesi', kembali ke pemisahan acak terstratifikasi
      seperti semula (perilaku Eksperimen 1 tidak berubah).
    """
    X = df[FITUR]
    y = df["label"]

    label_kelas = sorted(y.unique().tolist())

    if "sesi" in df.columns and df["sesi"].nunique() > 1:
        grup = df["sesi"]
        if uji_sesi is not None:
            # Tahan satu sesi tertentu sebagai data uji (mis. latih sesi 1-3,
            # uji sesi 4) — paling mudah dijelaskan saat sidang.
            mask_uji = grup.isin(uji_sesi)
            if not mask_uji.any():
                raise ValueError(
                    f"Sesi uji {uji_sesi} tidak ditemukan. "
                    f"Sesi tersedia: {sorted(grup.unique().tolist())}"
                )
            X_train, X_test = X[~mask_uji], X[mask_uji]
            y_train, y_test = y[~mask_uji], y[mask_uji]
            print(f"\n  Pemisahan per sesi (hold-out): uji = sesi {sorted(uji_sesi)}")
        else:
            # Pisahkan sesi secara acak hingga ~TEST_SIZE flow masuk uji,
            # tanpa ada sesi yang terpotong ke dua sisi.
            gss = GroupShuffleSplit(
                n_splits=1, test_size=TEST_SIZE, random_state=RANDOM_STATE
            )
            idx_train, idx_test = next(gss.split(X, y, groups=grup))
            X_train, X_test = X.iloc[idx_train], X.iloc[idx_test]
            y_train, y_test = y.iloc[idx_train], y.iloc[idx_test]
            sesi_uji = sorted(grup.iloc[idx_test].unique().tolist())
            print(f"\n  Pemisahan per sesi (acak): uji = sesi {sesi_uji}")
        if y_train.nunique() < len(label_kelas) or y_test.nunique() < len(label_kelas):
            print(
                "  [PERINGATAN] Tidak semua kelas muncul di kedua sisi. "
                "Pastikan tiap sesi memuat semua kelas (normal + serangan "
                "berjalan bersamaan), atau kumpulkan lebih banyak sesi."
            )
    else:
        # Stratifikasi menjaga proporsi kelas tetap sama antara data latih dan uji
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=TEST_SIZE, random_state=RANDOM_STATE, stratify=y
        )

    print(f"\n  Data latih : {len(X_train)} record")
    print(f"  Data uji   : {len(X_test)} record")

    hasil_semua = []
    model_terlatih = {}

    # --- Random Forest ---
    print("\n\nMelatih Random Forest...")
    rf = RandomForestClassifier(
        n_estimators=100,
        max_depth=None,
        min_samples_split=2,
        random_state=RANDOM_STATE,
        n_jobs=-1,
        class_weight="balanced",  # mengimbangi distribusi kelas yang timpang
    )
    rf.fit(X_train, y_train)
    hasil_rf = evaluasi("Random Forest", rf, X_test, y_test, label_kelas)
    hasil_rf["feature_importance"] = tampilkan_feature_importance(rf, "Random Forest")
    hasil_semua.append(hasil_rf)
    model_terlatih["Random Forest"] = rf

    # --- XGBoost ---
    print("\n\nMelatih XGBoost...")
    try:
        from xgboost import XGBClassifier

        # XGBoost membutuhkan label numerik, jadi dikodekan lebih dulu
        peta_label = {k: i for i, k in enumerate(label_kelas)}
        y_train_num = y_train.map(peta_label)
        y_test_num = y_test.map(peta_label)

        xgb = XGBClassifier(
            n_estimators=100,
            max_depth=6,
            learning_rate=0.3,
            random_state=RANDOM_STATE,
            n_jobs=-1,
            eval_metric="mlogloss",
        )
        xgb.fit(X_train, y_train_num)

        # Bungkus agar predict() mengembalikan label teks seperti Random Forest
        class XGBWrapper:
            def __init__(self, model, peta):
                self.model = model
                self.balik = {v: k for k, v in peta.items()}
                self.feature_importances_ = model.feature_importances_

            def predict(self, X):
                return np.array([self.balik[i] for i in self.model.predict(X)])

            def predict_proba(self, X):
                return self.model.predict_proba(X)

        xgb_wrap = XGBWrapper(xgb, peta_label)
        hasil_xgb = evaluasi("XGBoost", xgb_wrap, X_test, y_test, label_kelas)
        hasil_xgb["feature_importance"] = tampilkan_feature_importance(xgb_wrap, "XGBoost")
        hasil_semua.append(hasil_xgb)
        model_terlatih["XGBoost"] = xgb_wrap

    except ImportError:
        print("  XGBoost belum terpasang. Jalankan: pip install xgboost")
        print("  Pelatihan dilanjutkan dengan Random Forest saja.")

    # --- Perbandingan ---
    print(f"\n\n{'=' * 58}")
    print("  PERBANDINGAN MODEL")
    print(f"{'=' * 58}")
    print(f"  {'Model':<18}{'Accuracy':>11}{'Precision':>11}{'Recall':>10}{'F1':>9}")
    print(f"  {'-' * 56}")
    for h in hasil_semua:
        print(
            f"  {h['nama']:<18}"
            f"{h['accuracy']:>11.4f}"
            f"{h['precision_macro']:>11.4f}"
            f"{h['recall_macro']:>10.4f}"
            f"{h['f1_macro']:>9.4f}"
        )

    # F1-score dipakai sebagai dasar pemilihan karena menyeimbangkan
    # precision dan recall, sesuai kebutuhan sistem deteksi serangan
    terbaik = max(hasil_semua, key=lambda h: h["f1_macro"])
    print(f"\n  Model terbaik berdasarkan F1-score: {terbaik['nama']}")

    if simpan_model:
        import joblib

        Path("model").mkdir(exist_ok=True)
        joblib.dump(model_terlatih[terbaik["nama"]], "model/model_terbaik.pkl")
        joblib.dump(label_kelas, "model/label_kelas.pkl")

        with open("model/hasil_evaluasi.json", "w") as f:
            json.dump(
                {
                    "model_terbaik": terbaik["nama"],
                    "hasil": [
                        {k: v for k, v in h.items() if k != "laporan"}
                        for h in hasil_semua
                    ],
                },
                f,
                indent=2,
            )

        print("\n  Tersimpan:")
        print("    model/model_terbaik.pkl")
        print("    model/label_kelas.pkl")
        print("    model/hasil_evaluasi.json")

    return hasil_semua


def main():
    parser = argparse.ArgumentParser(
        description="Pelatihan dan perbandingan model klasifikasi serangan jaringan"
    )
    parser.add_argument("dataset", nargs="?", help="File CSV dataset berlabel")
    parser.add_argument(
        "--gabung",
        nargs="+",
        metavar="FILE",
        help="Gabungkan beberapa dataset berlabel menjadi satu",
    )
    parser.add_argument("-o", "--output", default="dataset_gabungan.csv")
    parser.add_argument(
        "--tanpa-simpan",
        action="store_true",
        help="Jangan simpan model hasil pelatihan",
    )
    parser.add_argument(
        "--uji-sesi",
        type=int,
        nargs="+",
        metavar="N",
        help="Tahan sesi tertentu sebagai data uji (mis. --uji-sesi 4). "
        "Tanpa opsi ini, bila ada kolom 'sesi' sesi dipisah acak per grup.",
    )
    args = parser.parse_args()

    if args.gabung:
        print("Menggabungkan dataset:")
        gabung_dataset(args.gabung, args.output)
        return

    if not args.dataset:
        parser.print_help()
        sys.exit(1)

    print(f"Memuat dataset: {args.dataset}")
    df = pd.read_csv(args.dataset)

    print("\nPemeriksaan dataset:")
    if not periksa_dataset(df):
        sys.exit(1)

    latih(df, simpan_model=not args.tanpa_simpan, uji_sesi=args.uji_sesi)


if __name__ == "__main__":
    main()
