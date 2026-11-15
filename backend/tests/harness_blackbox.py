"""
Harness black-box otomatis: memutar ulang flow nfdump TEREKAM (mis. data uji
flows_sesi4.csv) ke backend lewat API publiknya, lalu memeriksa hasilnya
terhadap ekspektasi tiap skenario SK-01..SK-06. Tidak butuh lab GNS3/VyOS:
backend berjalan di dalam proses (TestClient) dengan DRY_RUN=true dan
DIR_STATUS sementara, jadi aman dijalankan kapan saja dan hasilnya dapat
diulang (pelengkap uji lab langsung, bukan pengganti).

Yang diuji persis jalur produksi: /api/masuk -> /api/ingest (token) ->
pekerja -> model -> gerbang keputusan -> mitigasi (dry-run) -> /api/riwayat,
/api/terblokir, setujui/tolak/cabut.

Pakai (dari akar repo, venv backend):
  python backend/tests/harness_blackbox.py data/exp2/flows_sesi4.csv
  python backend/tests/harness_blackbox.py data/exp2/flows_sesi4.csv --jendela 5 \
      --keluar hasil/harness_blackbox.csv

Skenario dibentuk dengan menyaring flow terekam per jendela 60 detik:
  SK-01 hanya flow tanpa alamat 192.168.20.x       -> 0 insiden
  SK-02 hanya flow .20.31-250 <-> 192.168.30.10     -> ddos_flood blokir otomatis
  SK-03 jendela UTUH berisi pemindai .20.11-30 >=20 flow -> port_scanning blokir otomatis
  SK-04 SK-01 + SK-02 dalam jendela yang sama        -> ddos, 0 klien .10.x diblokir
  SK-05 SK-02 dengan AMBANG_CONF_BLOKIR=1.01         -> antrean; setujui/tolak benar
  SK-06 cabut satu IP terblokir                      -> hilang dari /api/terblokir
  BB-x  ingest tanpa token -> 401; badan > INGEST_MAKS_MB -> 413
Kode keluar 0 bila semua LULUS.
"""
import argparse
import csv
import ipaddress
import os
import sys
import tempfile
import time
from collections import defaultdict
from pathlib import Path

DIR_BACKEND = Path(__file__).resolve().parent.parent
DIR_REPO = DIR_BACKEND.parent
sys.path.insert(0, str(DIR_BACKEND))
sys.path.insert(0, str(DIR_REPO / "ml"))

import keamanan as km  # noqa: E402

PASSWORD = "harness-blackbox-" + os.urandom(6).hex()
TOKEN = "harness-token-" + os.urandom(6).hex()
# Dipasang sebelum konfigurasi diimpor: tidak pernah menyentuh router
os.environ.update({
    "DRY_RUN": "true", "SUMBER": "ingest",
    "ADMIN_PASSWORD_HASH": km.buat_hash(PASSWORD), "INGEST_TOKEN": TOKEN,
    "ADMIN_SUMBER": "127.0.0.1,::1,testclient", "INGEST_SUMBER": "127.0.0.1,::1,testclient",
    "DIR_STATUS": tempfile.mkdtemp(prefix="ndr_harness_"),
    "INGEST_MAKS_MB": os.environ.get("INGEST_MAKS_MB", "20"),
})

HEADER = "ts,td,pr,sa,sp,da,dp,flg,pkt,byt"
KORBAN = "192.168.30.10"


def ip(s):
    return ipaddress.ip_address(s.strip())


def oktet(alamat, prefix):
    a = alamat.strip()
    return int(a.rsplit(".", 1)[1]) if a.startswith(prefix + ".") else None


def pemindai(a):
    o = oktet(a, "192.168.20")
    return o is not None and 11 <= o <= 30


def penyerang_flood(a):
    o = oktet(a, "192.168.20")
    return o is not None and 31 <= o <= 250


def baca_jendela(path):
    """Kelompokkan baris data (10 kolom) per menit ts -> {'YYYYmmddHHMM': [baris]}."""
    per = defaultdict(list)
    with open(path, errors="replace") as f:
        for baris in f:
            baris = baris.rstrip("\r\n")
            if baris.count(",") != 9 or baris.startswith("ts,"):
                continue
            ts = baris.split(",", 1)[0].strip()
            per[ts[:16].replace("-", "").replace(" ", "").replace(":", "")].append(baris)
    return per


def saring(baris_list, syarat):
    hasil = []
    for b in baris_list:
        k = b.split(",")
        sa, da = k[3].strip(), k[5].strip()
        if syarat(sa, da):
            hasil.append(b)
    return hasil


def tanpa_penyerang(sa, da):
    return not sa.startswith("192.168.20.") and not da.startswith("192.168.20.")


def hanya_flood(sa, da):
    return (penyerang_flood(sa) and da == KORBAN) or (sa == KORBAN and penyerang_flood(da))


def hanya_scan(sa, da):
    return pemindai(sa) or pemindai(da)


class Harness:
    def __init__(self, klien, cfg, main):
        self.k, self.cfg, self.main = klien, cfg, main
        self.hasil = []

    def kirim(self, baris, nama, token=True):
        h = {"Content-Type": "text/csv", "X-Nama-File": nama}
        if not token:
            h["Authorization"] = ""
        return self.k.post("/api/ingest", content=(HEADER + "\n" + "\n".join(baris) + "\n").encode(),
                           headers=h)

    def tunggu(self, batas=120):
        akhir = time.time() + batas
        while time.time() < akhir:
            if self.main.antrean._unfinished_tasks == 0:
                return
            time.sleep(0.2)
        raise RuntimeError("antrean backend tidak selesai")

    def insiden_file(self, nama):
        data = self.k.get("/api/riwayat", params={"jenis": "insiden", "limit": 500}).json()["data"]
        return [e for e in data if e.get("nama_file") == nama]

    def terblokir(self):
        return {d["ip"] for d in self.k.get("/api/terblokir").json()["data"]}

    def catat(self, sk, jendela, lulus, ket, insiden=()):
        lat = [e["latensi_detik"]["deteksi"] for e in insiden if e.get("latensi_detik")]
        self.hasil.append({"skenario": sk, "jendela": jendela, "lulus": lulus,
                           "jumlah_insiden": len(insiden),
                           "kelas": " ".join(sorted({e["kelas"] for e in insiden})),
                           "status": " ".join(sorted({e["status"] for e in insiden})),
                           "conf_min": min((e["confidence"] for e in insiden), default=""),
                           "keterangan": ket, "n_latensi": len(lat)})
        tanda = "LEWAT" if lulus is None else ("LULUS" if lulus else "GAGAL")
        print(f"[{tanda}] {sk} {jendela}: {ket}")

    def jalankan(self, sk, jendela, baris, cek):
        if not baris:
            self.catat(sk, jendela, None, "dilewati: tidak ada flow untuk skenario ini")
            return []
        nama = f"nfcapd.{jendela}.{sk}"
        r = self.kirim(baris, nama)
        if r.status_code != 202:
            self.catat(sk, jendela, False, f"ingest HTTP {r.status_code}")
            return []
        self.tunggu()
        ins = self.insiden_file(nama)
        lulus, ket = cek(ins)
        self.catat(sk, jendela, lulus, f"{len(baris)} flow; {ket}", ins)
        return ins


def klien_10x(ips):
    return sorted(i for i in ips if i.startswith("192.168.10."))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("csv", help="CSV nfdump mentah terekam (mis. data/exp2/flows_sesi4.csv)")
    ap.add_argument("--jendela", type=int, default=3, help="jumlah jendela per skenario (default 3)")
    ap.add_argument("--keluar", help="simpan tabel hasil ke CSV")
    a = ap.parse_args()

    import logging
    logging.getLogger("httpx").setLevel(logging.WARNING)
    from fastapi.testclient import TestClient
    import konfigurasi as cfg
    import main as backend

    per = baca_jendela(a.csv)
    print(f"{sum(map(len, per.values()))} flow dalam {len(per)} jendela dari {a.csv}")

    def pilih(syarat, minimal):
        jw = [(w, saring(b, syarat)) for w, b in sorted(per.items())]
        return [(w, b) for w, b in jw if len(b) >= minimal][:a.jendela]

    with TestClient(backend.app, headers={"Authorization": f"Bearer {TOKEN}"}) as k:
        assert k.post("/api/masuk", json={"password": PASSWORD}).status_code == 200
        H = Harness(k, cfg, backend)

        for w, b in pilih(tanpa_penyerang, 50):
            H.jalankan("SK-01", w, b, lambda ins: (not ins, f"{len(ins)} insiden (harus 0)"))

        def cek_flood(ins):
            d = [e for e in ins if e["kelas"] == "ddos_flood" and e["kunci"] == KORBAN]
            ok = bool(d) and all(e["status"] == "blokir_otomatis" for e in d)
            bocor = klien_10x(H.terblokir())
            return ok and not bocor, (f"{len(d)} ddos kunci {KORBAN}, "
                                      f"status {sorted({e['status'] for e in d})}, klien .10.x terblokir={bocor}")
        for w, b in pilih(hanya_flood, 20):
            H.jalankan("SK-02", w, b, cek_flood)

        def cek_scan(ins):
            s = [e for e in ins if e["kelas"] == "port_scanning"]
            ok = bool(s) and all(pemindai(e["kunci"]) and e["status"] == "blokir_otomatis" for e in s)
            return ok, f"{len(s)} scan, kunci {sorted({e['kunci'] for e in s})}"
        # SK-03 memakai JENDELA UTUH: fitur unique_src_ip_per_dst dihitung dari
        # seluruh jendela, jadi menyaring hanya flow pemindai membuat nilainya
        # palsu (mis. 3, padahal di jendela asli 157) dan scan terbaca normal.
        # Dipilih jendela yang punya satu pemindai dengan >= MIN_FLOW_INSIDEN flow.
        def ada_pemindai_cukup(baris):
            hitung = defaultdict(int)
            for x in baris:
                sa = x.split(",")[3].strip()
                if pemindai(sa):
                    hitung[sa] += 1
            return max(hitung.values(), default=0) >= cfg.MIN_FLOW_INSIDEN
        jendela_scan = [(w, b) for w, b in sorted(per.items()) if ada_pemindai_cukup(b)][:a.jendela]
        for w, b in jendela_scan:
            H.jalankan("SK-03", w, b, cek_scan)

        normal = dict(pilih(tanpa_penyerang, 50))
        for w, b in pilih(hanya_flood, 20):
            campur = normal.get(w) or next(iter(normal.values()), [])
            H.jalankan("SK-04", w, campur + b, cek_flood)

        # SK-05: paksa antrean, setujui satu, tolak satu
        asli = cfg.AMBANG_CONF_BLOKIR
        cfg.AMBANG_CONF_BLOKIR = 1.01
        try:
            antre = []
            # Flood + scan supaya antrean berisi >= 2 insiden walau CSV pendek
            for w, b in pilih(hanya_flood, 20) + pilih(hanya_scan, 20):
                antre += H.jalankan("SK-05", w, b, lambda ins: (
                    bool(ins) and all(e["status"] == "menunggu_persetujuan" for e in ins),
                    f"{len(ins)} insiden ke antrean"))
        finally:
            cfg.AMBANG_CONF_BLOKIR = asli
        if len(antre) >= 2:
            x, y = antre[0], antre[1]
            r1 = k.post(f"/api/mitigasi/setujui/{x['id']}")
            blok = H.terblokir()
            ok1 = r1.status_code == 200 and set(x["ip_kandidat"]) <= blok
            H.catat("SK-05", "setujui", ok1, f"#{x['id']} {len(x['ip_kandidat'])} IP -> HTTP {r1.status_code}, "
                    f"latensi mitigasi {r1.json().get('latensi_detik', {}).get('mitigasi') if r1.status_code == 200 else '-'} s")
            baru = set(y["ip_kandidat"]) - set(x["ip_kandidat"]) - blok
            r2 = k.post(f"/api/mitigasi/tolak/{y['id']}")
            ok2 = r2.status_code == 200 and not (baru & H.terblokir())
            H.catat("SK-05", "tolak", ok2, f"#{y['id']} -> HTTP {r2.status_code}, kandidat tidak diblokir")
        else:
            H.catat("SK-05", "-", None, "dilewati: butuh >=2 insiden antrean")

        blok = sorted(H.terblokir())
        if blok:
            target = blok[0]
            r = k.post("/api/mitigasi/cabut", json={"ip": target})
            H.catat("SK-06", "cabut", r.status_code == 200 and target not in H.terblokir(),
                    f"cabut {target} -> HTTP {r.status_code}")

        r = H.kirim(["x"], "nfcapd.tanpa_token", token=False)
        H.catat("BB-token", "-", r.status_code == 401, f"ingest tanpa token -> HTTP {r.status_code}")
        besar = b"a" * (cfg.INGEST_MAKS_MB * 1024 * 1024 + 1)
        r = k.post("/api/ingest", content=besar, headers={"Content-Type": "text/csv"})
        H.catat("BB-413", "-", r.status_code == 413, f"badan > {cfg.INGEST_MAKS_MB} MB -> HTTP {r.status_code}")

    if a.keluar:
        Path(a.keluar).parent.mkdir(parents=True, exist_ok=True)
        with open(a.keluar, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=list(H.hasil[0]))
            w.writeheader()
            w.writerows(H.hasil)
        print(f"Tabel hasil -> {a.keluar}")
    gagal = [h for h in H.hasil if h["lulus"] is False]
    lewat = [h for h in H.hasil if h["lulus"] is None]
    print(f"\nRingkasan: {len(H.hasil) - len(gagal) - len(lewat)} lulus, {len(gagal)} gagal, {len(lewat)} dilewati")
    sys.exit(1 if gagal else 0)


if __name__ == "__main__":
    main()
