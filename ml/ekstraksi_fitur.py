"""
ekstraksi_fitur.py
==================
Mengubah flow record NetFlow (hasil nfdump) menjadi dataset berisi 10 fitur
sesuai Tabel 3.3 pada proposal.

Alur pemakaian:
    1. Di node Collector, ekspor flow record ke CSV:
         nfdump -R /data/nfcapd -o csv > flows.csv
    2. Salin flows.csv ke mesin tempat script ini dijalankan
    3. Jalankan:
         python ekstraksi_fitur.py flows.csv --label normal -o dataset_normal.csv

Sepuluh fitur yang dihasilkan:
    duration, packet_count, byte_count, dst_port_count, avg_packet_size,
    flow_rate, syn_flag_count, unique_src_ip_per_dst, protocol, inter_arrival_time
"""

import argparse
import sys

import numpy as np
import pandas as pd

# Jendela waktu (detik) untuk menghitung fitur agregat seperti dst_port_count
# dan unique_src_ip_per_dst. Nilai ini menentukan seberapa peka sistem
# terhadap pola Port Scanning yang tersebar dalam waktu.
WINDOW_SECONDS = 60

# --- Estimasi packet count ---
# Pada lingkungan uji (VyOS rolling dengan ipt_NETFLOW), field packet count
# tidak terisi oleh exporter (selalu nol) meskipun byte count terisi benar.
# Karena trafik uji bersifat seragam, packet count diestimasi dengan membagi
# byte count dengan perkiraan ukuran rata-rata paket.
#
# Nilai default 84 byte diambil dari pengamatan langsung pada flow record:
# paket SYN pemindaian dan flood tercatat sekitar 120-132 byte per flow yang
# umumnya berisi 1-2 paket, sehingga rata-rata mendekati 60-90 byte/paket.
# Sesuaikan nilai ini bila karakteristik trafikmu berbeda.
ESTIMASI_UKURAN_PAKET = 84

# Bila True, packet_count yang bernilai nol akan diestimasi dari byte_count.
# Set False bila exporter NetFlow-mu sudah mengisi packet count dengan benar.
ESTIMASI_PACKET_COUNT = True

# Berapa banyak flow yang packet_count-nya benar-benar diestimasi pada ekstraksi
# terakhir (0 = exporter mengisi field paket, jadi tidak ada yang diestimasi).
_JML_TERESTIMASI = 0

# Pemetaan nama protokol ke nomor, supaya model menerima input numerik
PROTOCOL_MAP = {"TCP": 6, "UDP": 17, "ICMP": 1}

FEATURE_COLUMNS = [
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


def set_window(detik):
    """Mengubah jendela waktu agregasi secara global."""
    global WINDOW_SECONDS
    WINDOW_SECONDS = detik


# Urutan kolom default untuk ekspor nfdump TANPA header, yakni:
#   nfdump -R /data/nfcapd -o "fmt:%ts,%td,%pr,%sa,%sp,%da,%dp,%flg,%pkt,%byt"
# Dipasang otomatis oleh baca_nfdump_csv bila file tidak punya baris header,
# sehingga langkah `sed -i '1i ts,td,...'` manual tidak lagi diperlukan.
KOLOM_FMT_DEFAULT = ["ts", "td", "pr", "sa", "sp", "da", "dp", "flg", "pkt", "byt"]

# Nama-nama yang, bila muncul di baris pertama, menandakan baris itu HEADER
# (bukan data flow). Dipakai untuk mendeteksi ada/tidaknya header.
_NAMA_HEADER = {
    "ts", "te", "td", "first", "firstseen", "last", "lastseen",
    "pr", "proto", "protocol", "sa", "da", "srcip", "dstip", "sp", "dp",
}


def _punya_header(path):
    """True bila baris pertama file berisi nama kolom, bukan data flow."""
    with open(path, "r", errors="replace") as f:
        baris1 = f.readline()
    token = [t.strip().lower() for t in baris1.split(",")]
    return any(t in _NAMA_HEADER for t in token)


def baca_nfdump_csv(path):
    """
    Membaca output nfdump, baik yang BERHEADER (`-o csv`) maupun yang TANPA
    header (`-o fmt:...`). Bila tidak ada header, nama kolom default
    (KOLOM_FMT_DEFAULT) dipasang otomatis — jadi `sed` manual tidak perlu lagi.

    nfdump menambahkan baris ringkasan di bagian akhir file yang bukan data
    flow, sehingga baris-baris tersebut perlu dibuang lebih dulu.
    """
    # skipinitialspace: format kustom nfdump (-o fmt:) menambahkan spasi
    # untuk merapikan kolom, misalnya ", 192.168.20.10"
    if _punya_header(path):
        df = pd.read_csv(path, low_memory=False, skipinitialspace=True)
    else:
        # Tanpa header: pasang nama kolom default HANYA bila jumlah kolomnya
        # cocok; kalau tidak, baca apa adanya sambil beri peringatan.
        probe = pd.read_csv(path, header=None, nrows=1, skipinitialspace=True)
        if probe.shape[1] == len(KOLOM_FMT_DEFAULT):
            df = pd.read_csv(path, header=None, names=KOLOM_FMT_DEFAULT,
                             low_memory=False, skipinitialspace=True)
        else:
            print(
                f"PERINGATAN: file tidak berheader dan jumlah kolomnya "
                f"({probe.shape[1]}) tidak sama dengan {len(KOLOM_FMT_DEFAULT)} "
                f"kolom default. File dibaca apa adanya; periksa format ekspornya."
            )
            df = pd.read_csv(path, header=None, low_memory=False, skipinitialspace=True)
    df.columns = [str(c).strip() for c in df.columns]
    for c in df.columns:
        if df[c].dtype == object:
            df[c] = df[c].astype(str).str.strip()

    # Buang baris ringkasan: baris valid selalu punya nilai pada kolom waktu
    if "ts" in df.columns:
        df = df[df["ts"].notna()]
        df = df[~df["ts"].astype(str).str.contains("Summary|Total|No matching", na=False)]

    return df.reset_index(drop=True)


def normalisasi_kolom(df):
    """
    Menyeragamkan nama kolom nfdump ke nama internal.

    Nama kolom nfdump bisa berbeda antar versi, jadi pemetaan dibuat longgar
    dan hanya mengambil kolom yang benar-benar dibutuhkan.
    """
    kandidat = {
        "ts": ["ts", "firstseen", "first"],
        "te": ["te", "lastseen", "last"],
        "td": ["td", "duration"],
        "sa": ["sa", "srcip", "src4_addr", "srcaddr"],
        "da": ["da", "dstip", "dst4_addr", "dstaddr"],
        "sp": ["sp", "srcport"],
        "dp": ["dp", "dstport"],
        "pr": ["pr", "proto", "protocol"],
        "flg": ["flg", "flags"],
        "ipkt": ["ipkt", "packets", "pkts", "pkt"],
        "ibyt": ["ibyt", "bytes", "byt", "byte"],
    }

    kolom_asli = {c.lower().strip(): c for c in df.columns}
    hasil = pd.DataFrame(index=df.index)

    # Format CSV bawaan nfdump 1.7 tidak menyertakan TCP flags
    if not any(a in kolom_asli for a in ("flg", "flags")):
        print(
            "PERINGATAN: kolom TCP flags tidak ditemukan, syn_flag_count akan "
            "bernilai 0. Ekspor ulang dengan format kustom yang memuat %flg."
        )

    for nama_internal, alias_list in kandidat.items():
        for alias in alias_list:
            if alias in kolom_asli:
                hasil[nama_internal] = df[kolom_asli[alias]]
                break
        else:
            hasil[nama_internal] = np.nan

    return hasil


def hitung_syn_flag(flg):
    """
    Menghitung indikator flag SYN dari kolom flags nfdump.

    nfdump menuliskan flags sebagai string posisional, contoh '....S.' atau
    '.AS...'. Huruf S pada string tersebut menandakan flag SYN aktif.
    Nilai yang dikembalikan adalah 1 bila SYN aktif, 0 bila tidak.
    """
    if not isinstance(flg, str):
        return 0
    return 1 if "S" in flg.upper() else 0


def hitung_fitur_agregat(df):
    """
    Menghitung dua fitur yang tidak bisa diambil dari satu flow saja:

    - dst_port_count        : jumlah port tujuan unik yang diakses satu IP
                              sumber dalam satu jendela waktu. Nilai tinggi
                              merupakan indikator kuat Port Scanning.
    - unique_src_ip_per_dst : jumlah IP sumber unik yang mengakses satu IP
                              tujuan dalam satu jendela waktu. Nilai tinggi
                              merupakan indikator serangan terdistribusi.
    """
    df = df.copy()
    df["window"] = (df["ts_epoch"] // WINDOW_SECONDS).astype("int64")

    port_per_src = (
        df.groupby(["window", "sa"])["dp"]
        .nunique()
        .rename("dst_port_count")
        .reset_index()
    )

    src_per_dst = (
        df.groupby(["window", "da"])["sa"]
        .nunique()
        .rename("unique_src_ip_per_dst")
        .reset_index()
    )

    df = df.merge(port_per_src, on=["window", "sa"], how="left")
    df = df.merge(src_per_dst, on=["window", "da"], how="left")

    return df


def hitung_inter_arrival(df):
    """
    Menghitung rata-rata selisih waktu kedatangan antar paket dalam satu flow.

    Dihitung sebagai durasi flow dibagi jumlah paket. Flow dengan satu paket
    atau kurang diberi nilai 0 karena tidak ada jarak antar paket yang bisa
    dihitung.
    """
    hasil = np.where(
        df["packet_count"] > 1,
        df["duration"] / df["packet_count"].replace(0, np.nan),
        0.0,
    )
    return pd.Series(hasil, index=df.index).fillna(0.0)


def ekstrak(path_csv, label=None, sertakan_ip=False, estimasi_paksa=False):
    """
    Fungsi utama: membaca CSV nfdump dan mengembalikan DataFrame 10 fitur.

    sertakan_ip : bool
        Bila True, kolom `sa`, `da`, `dp`, dan `window` (indeks jendela
        WINDOW_SECONDS dari `ts`) ikut dikembalikan di belakang 10 fitur.
        Kolom ini dibawa dari DataFrame yang sama, jadi urutan barisnya pasti
        cocok. Bila False, keluaran sama persis dengan sebelumnya.
    estimasi_paksa : bool
        Bila True, packet_count SELURUH flow diestimasi dari byte_count
        (byte / ESTIMASI_UKURAN_PAKET), sama seperti saat data latih dibuat,
        meskipun exporter mengisi field paket.
    """
    mentah = baca_nfdump_csv(path_csv)
    if mentah.empty:
        raise ValueError("File tidak berisi flow record yang valid.")

    df = normalisasi_kolom(mentah)

    # --- Waktu ---
    df["ts_dt"] = pd.to_datetime(df["ts"], errors="coerce")
    df = df[df["ts_dt"].notna()].reset_index(drop=True)
    # Detik sejak epoch, dihitung lewat selisih waktu agar tidak bergantung
    # pada resolusi internal pandas (pandas 3 memakai mikrodetik, versi lama
    # memakai nanodetik; asumsi resolusi yang keliru merusak jendela waktu)
    df["ts_epoch"] = (
        (df["ts_dt"] - pd.Timestamp("1970-01-01")) // pd.Timedelta(seconds=1)
    ).astype("int64")

    # --- Fitur dasar per flow ---
    # Format kustom nfdump menulis durasi sebagai "HH:MM:SS.mmm",
    # sedangkan format lain menulisnya sebagai angka detik
    td = df["td"].astype(str).str.strip()
    if td.str.contains(":").any():
        df["duration"] = pd.to_timedelta(td, errors="coerce").dt.total_seconds().fillna(0.0)
    else:
        df["duration"] = pd.to_numeric(td, errors="coerce").fillna(0.0)
    df["packet_count"] = pd.to_numeric(df["ipkt"], errors="coerce").fillna(0).astype("int64")
    df["byte_count"] = pd.to_numeric(df["ibyt"], errors="coerce").fillna(0).astype("int64")
    df["dp"] = pd.to_numeric(df["dp"], errors="coerce").fillna(0).astype("int64")

    # --- Estimasi packet count bila exporter tidak mengisinya ---
    # Bila seluruh packet_count bernilai nol padahal byte_count terisi,
    # itu tanda exporter tidak mengirim field packet count. Dalam kasus ini
    # packet count diestimasi dari byte count.
    global _JML_TERESTIMASI
    _JML_TERESTIMASI = 0
    if estimasi_paksa:
        df["packet_count"] = 0
    if ESTIMASI_PACKET_COUNT or estimasi_paksa:
        packet_kosong = (df["packet_count"] == 0) & (df["byte_count"] > 0)
        _JML_TERESTIMASI = int(packet_kosong.sum())
        if packet_kosong.any():
            estimasi = (df["byte_count"] / ESTIMASI_UKURAN_PAKET).round().clip(lower=1)
            df.loc[packet_kosong, "packet_count"] = estimasi[packet_kosong].astype("int64")

    # --- Protokol ---
    proto_str = df["pr"].astype(str).str.upper().str.strip()
    df["protocol"] = proto_str.map(PROTOCOL_MAP)
    # Bila nfdump sudah menuliskan protokol sebagai angka, pakai angkanya
    df["protocol"] = df["protocol"].fillna(
        pd.to_numeric(df["pr"], errors="coerce")
    ).fillna(0).astype("int64")

    # --- Ukuran dan laju paket ---
    df["avg_packet_size"] = np.where(
        df["packet_count"] > 0,
        df["byte_count"] / df["packet_count"],
        0.0,
    )
    df["flow_rate"] = np.where(
        df["duration"] > 0,
        df["packet_count"] / df["duration"],
        0.0,
    )

    # --- Flag SYN ---
    df["syn_flag_count"] = df["flg"].apply(hitung_syn_flag)

    # --- Fitur agregat berbasis jendela waktu ---
    df = hitung_fitur_agregat(df)

    # --- Inter arrival time ---
    df["inter_arrival_time"] = hitung_inter_arrival(df)

    hasil = df[FEATURE_COLUMNS].copy()
    hasil = hasil.replace([np.inf, -np.inf], 0.0).fillna(0.0)

    if sertakan_ip:
        hasil["sa"] = df["sa"].astype(str)
        hasil["da"] = df["da"].astype(str)
        hasil["dp"] = df["dp"]
        hasil["window"] = df["window"]

    if label is not None:
        hasil["label"] = label

    return hasil


def main():
    parser = argparse.ArgumentParser(
        description="Ekstraksi 10 fitur NetFlow untuk penelitian NDR"
    )
    parser.add_argument("input", help="File CSV hasil `nfdump -o csv`")
    parser.add_argument(
        "--label",
        choices=["normal", "ddos_flood", "port_scanning"],
        help="Label kelas untuk seluruh flow di file ini",
    )
    parser.add_argument(
        "-o", "--output", default="dataset.csv", help="Nama file CSV keluaran"
    )
    parser.add_argument(
        "--window",
        type=int,
        default=WINDOW_SECONDS,
        help=f"Jendela waktu agregasi dalam detik (default {WINDOW_SECONDS})",
    )
    args = parser.parse_args()

    set_window(args.window)

    try:
        df = ekstrak(args.input, args.label)
    except Exception as e:
        print(f"Gagal memproses: {e}", file=sys.stderr)
        sys.exit(1)

    df.to_csv(args.output, index=False)

    print(f"Berhasil mengekstrak {len(df)} flow record.")
    print(f"Tersimpan di: {args.output}")
    if args.label:
        print(f"Label: {args.label}")

    # Beri tahu HANYA bila ada packet count yang benar-benar diestimasi
    if ESTIMASI_PACKET_COUNT and _JML_TERESTIMASI > 0:
        print(
            f"\nCatatan: packet_count diestimasi dari byte_count "
            f"(ukuran paket ~{ESTIMASI_UKURAN_PAKET} byte) untuk "
            f"{_JML_TERESTIMASI:,} flow, karena exporter NetFlow tidak mengisi "
            f"field paket pada flow tersebut."
        )
    elif _JML_TERESTIMASI == 0:
        print("\nCatatan: packet_count dibaca langsung dari field paket NetFlow (tanpa estimasi).")

    print("\nRingkasan statistik:")
    print(df[FEATURE_COLUMNS].describe().T[["mean", "min", "max"]].round(3))

    # Peringatan dini bila ada fitur yang seluruhnya bernilai nol —
    # ini menandakan field tersebut tidak dikirim oleh exporter NetFlow
    kosong = [c for c in FEATURE_COLUMNS if df[c].sum() == 0]
    if kosong:
        print(
            "\nPERINGATAN: fitur berikut bernilai nol untuk semua record, "
            "periksa konfigurasi exporter NetFlow:"
        )
        for c in kosong:
            print(f"  - {c}")


if __name__ == "__main__":
    main()
