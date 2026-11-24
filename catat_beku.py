"""Mencatat keadaan yang DIBEKUKAN sebelum sesi 5 direkam (rencana Fase 4).

Mencatat commit hash kode, status worktree (harus bersih), SHA-256 model,
dan semua ambang gerbang keputusan yang dibaca backend (konfigurasi + .env).
Jalankan di ROOT repo dengan venv backend, SEBELUM perekaman sesi 5:
  .\\backend\\.venv\\Scripts\\python.exe catat_beku.py --keluar beku_sesi5.json
Simpan berkas JSON-nya; nilai di dalamnya ditulis di naskah BAB III/IV.
"""
import argparse
import hashlib
import json
import subprocess
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "backend"))

import konfigurasi as cfg  # noqa: E402


def git(*arg):
    return subprocess.run(["git", *arg], cwd=ROOT, capture_output=True, text=True).stdout.strip()


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for blok in iter(lambda: f.read(1 << 20), b""):
            h.update(blok)
    return h.hexdigest()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--keluar", default="beku_sesi5.json")
    a = ap.parse_args()
    kotor = git("status", "--porcelain", "--untracked-files=no")
    catatan = {
        "waktu": datetime.now().isoformat(timespec="seconds"),
        "commit": git("rev-parse", "HEAD"),
        "branch": git("rev-parse", "--abbrev-ref", "HEAD"),
        "worktree_bersih": not kotor,
        "berkas_berubah": kotor.splitlines(),
        "model": str(cfg.MODEL_PATH.relative_to(ROOT)),
        "model_sha256": sha256(cfg.MODEL_PATH),
        "ambang": {
            "MIN_FLOW_INSIDEN": cfg.MIN_FLOW_INSIDEN,
            "AMBANG_RASIO_SERANGAN": cfg.AMBANG_RASIO_SERANGAN,
            "AMBANG_CONF_BLOKIR": cfg.AMBANG_CONF_BLOKIR,
            "AMBANG_SEDANG": cfg.AMBANG_SEDANG,
            "AMBANG_TINGGI": cfg.AMBANG_TINGGI,
            "MAKS_BLOKIR_BARU_PER_JENDELA": cfg.MAKS_BLOKIR_BARU_PER_JENDELA,
            "DURASI_BLOKIR_MENIT": cfg.DURASI_BLOKIR_MENIT,
            "SUBNET_TERLINDUNG": list(cfg.SUBNET_TERLINDUNG),
            "SUBNET_BACKSCATTER": cfg.SUBNET_BACKSCATTER,
        },
    }
    Path(a.keluar).write_text(json.dumps(catatan, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps(catatan, indent=2, ensure_ascii=False))
    if kotor:
        print("\nPERINGATAN: ada berkas terlacak yang belum di-commit. Commit dulu, "
              "lalu jalankan ulang, supaya commit hash benar-benar mewakili kode yang dipakai.")


if __name__ == "__main__":
    main()
