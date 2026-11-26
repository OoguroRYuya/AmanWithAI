"""
banding_sesi.py
===============
Membandingkan sesi 1-5 dari sisi GENERATOR dan dari sisi HASIL MODEL, untuk
menjawab arahan "hasil sesi 4 dan sesi 5 harus sama". Skrip ini HANYA membaca:
model, ambang, dan kode tidak diubah, dan tidak ada yang dipilih dari hasilnya.

Pertanyaan yang dijawab:
  A. Apakah generator sesi 5 (ber-seed) menghasilkan sebaran perintah nmap yang
     setara dengan generator lama sesi 1-4? (jenis scan, cakupan port, lebar
     rentang, kecepatan; uji chi-kuadrat)
  B. Recall scan per jenis nmap dan per cakupan port untuk tiap sesi, model
     final XGBoost dan Random Forest pembanding. Kalau recall per jenis sesi 4
     dan sesi 5 sama, penurunan sesi 5 berasal dari CAMPURAN perintah, bukan
     dari model atau lingkungan yang berubah.
  C. Recall scan dan F1 makro sesi 5 bila campuran (jenis x cakupan) disamakan
     dengan sesi 4 (post-stratifikasi, deskriptif).
  D. Seberapa besar F1 bisa berbeda antar sesi HANYA karena undian perintah
     nmap: bootstrap atas perintah (run) di dalam tiap sesi -> selang 95%.

Jalankan di GNS3 VM (folder ml, branch revisi2). Satu --sesi per sesi:
  NOMOR, CSV flow mentah nfdump, log serang_scan.sh sesi itu.

    cd ~/AmanWithAI/ml
    python3 banding_sesi.py \
      --sesi 1 ~/dataset_retrain/flows_sesi1.csv ~/dataset_retrain/scan_sesi1.log \
      --sesi 2 ~/dataset_retrain/flows_sesi2.csv ~/dataset_retrain/scan_sesi2.log \
      --sesi 3 ~/dataset_retrain/flows_sesi3.csv ~/dataset_retrain/scan_sesi3.log \
      --sesi 4 ~/dataset_retrain/flows_sesi4.csv ~/dataset_retrain/scan_sesi4.log \
      --sesi 5 ~/dataset_retrain/bersih_sesi5.csv ~/dataset_retrain/scan_sesi5.log \
      --gabungan ~/eksperimen_fitur/dataset_gabungan.csv \
      --keluar ~/hasil_revisi/banding_sesi

Sesi yang lognya tidak ada boleh dilewati; minimal sesi 4 dan 5.
--gabungan dipakai untuk melatih ulang RF pembanding (sesi 1-2, random_state 42).
"""
import argparse
import re
import tempfile
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import f1_score

import ekstraksi_fitur as ef

PREFIX_PENYERANG = "192.168.20."
RENTANG_SCAN = (11, 30)
RENTANG_FLOOD = (31, 250)
KELAS = ["ddos_flood", "normal", "port_scanning"]
B_BOOT = 2000


# ---------------------------------------------------------------- log nmap
def baca_log(path):
    pola = re.compile(r"^(\d+) nmap (-s\w) (.*?) -S (\d+\.\d+\.\d+\.\d+)(?: timeout=(\d+))?")
    rows = []
    for teks in Path(path).expanduser().read_text(errors="replace").splitlines():
        m = pola.match(teks.strip())
        if not m:
            continue
        t0, jenis, sisa, ip, batas = m.groups()
        if "--top-ports" in sisa:
            cak = "top-ports"
            lebar = int(re.search(r"--top-ports (\d+)", sisa).group(1))
        elif re.search(r"-p \d+-\d+", sisa):
            a, b = map(int, re.search(r"-p (\d+)-(\d+)", sisa).groups())
            cak = "rentang_1-N" if a == 1 else "rentang_acak"
            lebar = b - a + 1
        else:
            cak = "daftar"
            daftar = re.search(r"-p ([\d,]+)", sisa)
            lebar = len(daftar.group(1).split(",")) if daftar else np.nan
        if "--max-rate" in sisa:
            laju = "max-rate"
        elif "--scan-delay" in sisa:
            laju = "scan-delay"
        elif "-T2" in sisa:
            laju = "T2"
        else:
            laju = "T3-5"
        rows.append({"t0": int(t0), "jenis": jenis, "cakupan": cak, "lebar_port": lebar,
                     "laju": laju, "ip": ip, "batas": int(batas) if batas else 180,
                     "perintah": teks.strip().split(" ", 1)[1]})
    log = pd.DataFrame(rows).sort_values("t0").reset_index(drop=True)
    # run berikutnya dimulai setelah run ini selesai (generator berurutan)
    log["t_akhir"] = np.minimum(log["t0"] + log["batas"], log["t0"].shift(-1).fillna(np.inf))
    log["run"] = np.arange(len(log))
    return log


# ---------------------------------------------------------------- flow
def baca_flow(path):
    """Ekstrak 9 fitur; buang baris non-data nfdump (header/ringkasan)."""
    path = Path(path).expanduser()
    with open(path, errors="replace") as f:
        baris = [b for b in f if b.count(",") == 9]
    with tempfile.NamedTemporaryFile("w", suffix=".csv", delete=False) as t:
        t.writelines(baris)
    df = ef.ekstrak(t.name, sertakan_ip=True)
    Path(t.name).unlink()
    df = df[~df["da"].astype(str).str.startswith(PREFIX_PENYERANG)].reset_index(drop=True)
    okt = pd.to_numeric(df["sa"].str.rsplit(".", n=1).str[-1], errors="coerce")
    pyr = df["sa"].str.startswith(PREFIX_PENYERANG)
    df["label"] = "normal"
    df.loc[pyr & okt.between(*RENTANG_SCAN), "label"] = "port_scanning"
    df.loc[pyr & okt.between(*RENTANG_FLOOD), "label"] = "ddos_flood"
    return df


def kaitkan(scan, log, geser):
    """Isi kolom run untuk flow scan: IP sama dan jendela beririsan dengan run."""
    w0 = scan["window"].to_numpy() * ef.WINDOW_SECONDS + geser
    run = np.full(len(scan), -1)
    sa = scan["sa"].to_numpy()
    for r in log.itertuples():
        cocok = (sa == r.ip) & (w0 + ef.WINDOW_SECONDS > r.t0) & (w0 <= r.t_akhir)
        run[cocok] = r.run
    return run


def cari_geser(scan, log):
    """Jam flow nfdump bisa lokal (WIB) sedangkan log memakai epoch UTC."""
    terbaik = (0, -1.0)
    for jam in range(-12, 13):
        frac = (kaitkan(scan, log, jam * 3600) >= 0).mean()
        if frac > terbaik[1]:
            terbaik = (jam * 3600, frac)
    return terbaik


# ---------------------------------------------------------------- metrik
def f1_dari_cm(cm):
    """cm: dict (aktual, prediksi) -> jumlah. F1 makro 3 kelas."""
    f = []
    for k in KELAS:
        tp = cm.get((k, k), 0)
        fp = sum(cm.get((a, k), 0) for a in KELAS if a != k)
        fn = sum(cm.get((k, p), 0) for p in KELAS if p != k)
        f.append(0.0 if tp == 0 else 2 * tp / (2 * tp + fp + fn))
    return float(np.mean(f))


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--sesi", nargs=3, action="append", metavar=("N", "FLOW", "LOG"),
                    required=True)
    ap.add_argument("--gabungan", help="dataset_gabungan.csv (untuk RF pembanding)")
    ap.add_argument("--model", default="model/model_terbaik.pkl")
    ap.add_argument("--keluar", default="hasil_revisi/banding_sesi")
    ap.add_argument("--seed", type=int, default=20261125)
    a = ap.parse_args()
    keluar = Path(a.keluar).expanduser()
    keluar.mkdir(parents=True, exist_ok=True)
    rng = np.random.default_rng(a.seed)

    model = {"XGB": joblib.load(a.model)}
    if a.gabungan:
        from sklearn.ensemble import RandomForestClassifier
        g = pd.read_csv(Path(a.gabungan).expanduser())
        latih = g[g["sesi"].isin([1, 2])]
        rf = RandomForestClassifier(n_estimators=100, max_depth=None, min_samples_split=2,
                                    random_state=42, n_jobs=-1, class_weight="balanced")
        rf.fit(latih[ef.FEATURE_COLUMNS], latih["label"])
        model["RF"] = rf

    semua_log, semua_run, ringkas, cm_sesi = [], [], [], {}
    for n, p_flow, p_log in a.sesi:
        n = int(n)
        log = baca_log(p_log)
        log["sesi"] = n
        semua_log.append(log)
        df = baca_flow(p_flow)
        for nm, m in model.items():
            df[f"pred_{nm}"] = np.asarray(m.predict(df[ef.FEATURE_COLUMNS])).astype(str)
        scan = df[df["label"] == "port_scanning"].copy()
        geser, frac = cari_geser(scan, log)
        scan["run"] = kaitkan(scan, log, geser)
        print(f"Sesi {n}: {len(df)} flow ({df['label'].value_counts().to_dict()}), "
              f"{len(log)} perintah nmap, geser jam {geser // 3600:+d} h, "
              f"flow scan terkait log {frac:.1%}")
        # cek angka naskah
        for nm in model:
            ringkas.append({"sesi": n, "model": nm,
                            "f1_makro": round(f1_score(df["label"], df[f"pred_{nm}"],
                                                       labels=KELAS, average="macro"), 4),
                            "recall_scan": round((scan[f"pred_{nm}"] == "port_scanning").mean(), 4)})
            # confusion matrix tanpa flow scan yang terkait run (untuk bootstrap)
            tetap = df.drop(index=scan.index[scan["run"] >= 0])
            cm_sesi[(n, nm)] = tetap.groupby(["label", f"pred_{nm}"]).size().to_dict()
        # per run: jumlah flow per prediksi
        for (r,), gr in scan[scan["run"] >= 0].groupby(["run"]):
            baris = {"sesi": n, "run": r, "flow": len(gr)}
            for nm in model:
                vc = gr[f"pred_{nm}"].value_counts()
                for k in KELAS:
                    baris[f"{nm}_{k}"] = int(vc.get(k, 0))
            semua_run.append(baris)

    log = pd.concat(semua_log, ignore_index=True)
    run = pd.DataFrame(semua_run).merge(
        log[["sesi", "run", "jenis", "cakupan", "lebar_port", "laju", "perintah"]],
        on=["sesi", "run"], how="left")
    for nm in model:
        run[f"recall_{nm}"] = (run[f"{nm}_port_scanning"] / run["flow"]).round(4)
    log.to_csv(keluar / "log_semua_sesi.csv", index=False)
    run.to_csv(keluar / "recall_per_run.csv", index=False)
    pd.DataFrame(ringkas).to_csv(keluar / "f1_per_sesi.csv", index=False)

    print("\n== 0. F1 makro dan recall scan per sesi "
          "(cek: sesi 4 XGB 0,9757 RF 0,9596; sesi 5 XGB 0,9093 RF 0,9687)")
    print(pd.DataFrame(ringkas).pivot(index="sesi", columns="model").to_string())

    # ---- A. sebaran generator
    print("\n== A. Sebaran perintah nmap per sesi (dari log generator)")
    for kol in ("jenis", "cakupan", "laju"):
        t = pd.crosstab(log["sesi"], log[kol])
        print(f"\n[{kol}] jumlah perintah\n{t.to_string()}")
        t.to_csv(keluar / f"A_sebaran_{kol}.csv")
    lebar = log.groupby(["sesi", "cakupan"])["lebar_port"].median().unstack()
    print(f"\n[median lebar port per cakupan]\n{lebar.to_string()}")
    print("\n[jumlah perintah dan median flow per perintah]")
    print(run.groupby("sesi")["flow"].agg(["size", "median", "sum"]).to_string())
    try:
        from scipy.stats import chi2_contingency
        s5 = log[log["sesi"] == 5]
        for kol in ("jenis", "cakupan", "laju"):
            for nama, ref in (("sesi 1-4", log[log["sesi"] <= 4]), ("sesi 4", log[log["sesi"] == 4])):
                sub = pd.concat([ref, s5])
                t = pd.crosstab(sub["sesi"] == 5, sub[kol])
                if t.shape[0] == 2 and t.shape[1] > 1:
                    chi, p, dof, _ = chi2_contingency(t)
                    print(f"chi-kuadrat {kol}: sesi 5 vs {nama}: chi2={chi:.2f} dof={dof} p={p:.3f}")
    except ImportError:
        print("(scipy tidak ada, uji chi-kuadrat dilewati)")

    # ---- B. recall per jenis / cakupan per sesi
    print("\n== B. Recall scan per jenis dan per cakupan, tiap sesi (bobot flow)")
    tabel_b = []
    for kol in ("jenis", "cakupan"):
        for nm in model:
            agg = run.groupby(["sesi", kol])[["flow", f"{nm}_port_scanning"]].sum()
            agg["recall"] = (agg[f"{nm}_port_scanning"] / agg["flow"]).round(3)
            piv = agg["recall"].unstack(kol)
            fl = agg["flow"].unstack(kol)
            print(f"\n[{nm}] recall per {kol}\n{piv.to_string()}\n[flow]\n{fl.to_string()}")
            t = agg.reset_index().assign(model=nm, dimensi=kol).rename(columns={kol: "nilai"})
            tabel_b.append(t[["model", "dimensi", "sesi", "nilai", "flow", "recall"]])
    pd.concat(tabel_b).to_csv(keluar / "B_recall_per_jenis_cakupan.csv", index=False)

    # ---- C. post-stratifikasi: sesi 5 dengan campuran sesi 4
    print("\n== C. Sesi 5 bila campuran jenis x cakupan disamakan dengan sesi 4 (deskriptif)")
    sel = ["jenis", "cakupan"]
    tabel_c = []
    for nm in model:
        c = run.groupby(["sesi"] + sel)[["flow", f"{nm}_port_scanning"]].sum()
        r5 = (c.loc[5, f"{nm}_port_scanning"] / c.loc[5, "flow"])
        w4 = c.loc[4, "flow"] / c.loc[4, "flow"].sum()
        gab = pd.concat([w4.rename("w4"), r5.rename("r5")], axis=1)
        kosong = gab["r5"].isna() & gab["w4"].notna()
        tercakup = gab.loc[~kosong, "w4"].sum()
        std = (gab["w4"] * gab["r5"]).sum() / tercakup
        r4 = c.loc[4, f"{nm}_port_scanning"].sum() / c.loc[4, "flow"].sum()
        r5a = c.loc[5, f"{nm}_port_scanning"].sum() / c.loc[5, "flow"].sum()
        tabel_c.append({"model": nm, "recall_sesi4": round(r4, 4), "recall_sesi5": round(r5a, 4),
                        "recall_sesi5_campuran_sesi4": round(std, 4),
                        "bobot_sesi4_tercakup": round(tercakup, 3)})
    tc = pd.DataFrame(tabel_c)
    print(tc.to_string(index=False))
    tc.to_csv(keluar / "C_post_stratifikasi.csv", index=False)

    # ---- D. bootstrap atas perintah nmap
    print(f"\n== D. Selang 95% bootstrap atas perintah nmap ({B_BOOT} ulangan, seed {a.seed})")
    tabel_d = []
    for (n, nm), cm0 in cm_sesi.items():
        rs = run[run["sesi"] == n]
        if rs.empty:
            continue
        mat = rs[[f"{nm}_{k}" for k in KELAS]].to_numpy()
        f1s, recs = [], []
        for _ in range(B_BOOT):
            idx = rng.integers(0, len(rs), len(rs))
            tot = mat[idx].sum(0)
            cm = dict(cm0)
            for k, v in zip(KELAS, tot):
                cm[("port_scanning", k)] = cm.get(("port_scanning", k), 0) + int(v)
            f1s.append(f1_dari_cm(cm))
            recs.append(tot[2] / tot.sum())
        tabel_d.append({"sesi": n, "model": nm, "run": len(rs),
                        "f1_bawah": round(np.percentile(f1s, 2.5), 4),
                        "f1_tengah": round(np.median(f1s), 4),
                        "f1_atas": round(np.percentile(f1s, 97.5), 4),
                        "recall_scan_bawah": round(np.percentile(recs, 2.5), 4),
                        "recall_scan_atas": round(np.percentile(recs, 97.5), 4)})
    td = pd.DataFrame(tabel_d)
    print(td.to_string(index=False))
    td.to_csv(keluar / "D_bootstrap_per_sesi.csv", index=False)

    print(f"\nTersimpan di {keluar}")


if __name__ == "__main__":
    main()
