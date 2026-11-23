"""
saran_tindakan.py
=================
Menghasilkan narasi saran tindakan berbasis template, sesuai rancangan
subbab 3.5.1 pada proposal.

Pendekatan berbasis template dipilih, bukan Large Language Model, karena
jumlah kelas serangan terbatas pada dua jenis sehingga variasi narasi yang
dibutuhkan relatif sedikit. Pendekatan ini bersifat deterministik, tidak
memerlukan sumber daya komputasi tambahan, dan tidak bergantung pada
layanan eksternal.
"""

from datetime import datetime

# Ambang tingkat kepercayaan untuk menentukan apakah mitigasi otomatis
# disarankan atau cukup pemantauan lanjutan
AMBANG_TINGGI = 0.90
AMBANG_SEDANG = 0.70

TEMPLATE = {
    "ddos_flood": {
        "judul": "Terdeteksi Serangan DDoS Flood",
        "tingkat": "Tinggi",
        "deskripsi": (
            "Sistem mendeteksi pola trafik yang konsisten dengan serangan DDoS Flood "
            "dari alamat IP {src_ip} menuju {dst_ip} pada {waktu}. "
            "Trafik tercatat sebanyak {packet_count} paket ({byte_count} byte) "
            "dengan laju {flow_rate:.1f} paket per detik, "
            "jauh di atas pola trafik normal."
        ),
        "tindakan_tinggi": (
            "Disarankan melakukan pemblokiran sementara terhadap alamat IP {src_ip} "
            "melalui aturan firewall pada router selama {durasi_blokir} menit, "
            "kemudian memantau apakah aktivitas serupa berulang setelah blokir dicabut."
        ),
        "tindakan_sedang": (
            "Disarankan memantau alamat IP {src_ip} secara lebih ketat sebelum "
            "menerapkan pemblokiran, mengingat tingkat kepercayaan klasifikasi "
            "belum mencapai ambang tinggi."
        ),
        "dampak": (
            "Bila dibiarkan, serangan ini berpotensi menyebabkan layanan pada "
            "{dst_ip} tidak dapat diakses oleh pengguna sah."
        ),
    },
    "port_scanning": {
        "judul": "Terdeteksi Aktivitas Port Scanning",
        "tingkat": "Sedang",
        "deskripsi": (
            "Sistem mendeteksi aktivitas pemindaian port dari alamat IP {src_ip} "
            "terhadap {dst_ip} pada {waktu}. "
            "Tercatat {dst_port_count} port tujuan berbeda diakses dalam waktu singkat, "
            "yang merupakan indikator pemindaian jaringan."
        ),
        "tindakan_tinggi": (
            "Disarankan memblokir alamat IP {src_ip} selama {durasi_blokir} menit "
            "dan meninjau log akses pada {dst_ip} untuk memastikan tidak ada "
            "layanan yang berhasil diakses selama pemindaian berlangsung."
        ),
        "tindakan_sedang": (
            "Disarankan melakukan pemantauan lanjutan terhadap alamat IP {src_ip}. "
            "Pemblokiran dapat diterapkan apabila aktivitas pemindaian berlanjut "
            "atau meningkat intensitasnya."
        ),
        "dampak": (
            "Port Scanning umumnya merupakan tahap pengintaian sebelum serangan "
            "yang lebih serius, sehingga perlu ditindaklanjuti meskipun belum "
            "menimbulkan gangguan langsung."
        ),
    },
}


# Status keputusan mitigasi (sama dengan konstanta di backend/keputusan.py).
# Bila status diberikan, kalimat tindakan mengikuti keputusan sistem, bukan
# confidence saja, sehingga narasi tidak pernah menyarankan pemblokiran
# untuk insiden yang hanya dicatat (koreksi Pak Deni butir 46).
STATUS_BLOKIR_OTOMATIS = "blokir_otomatis"
STATUS_MENUNGGU = "menunggu_persetujuan"
STATUS_DICATAT = "dicatat"
STATUS_DISETUJUI = "disetujui"
STATUS_DITOLAK = "ditolak"

TINDAKAN_STATUS = {
    STATUS_BLOKIR_OTOMATIS: (
        "Sistem telah memblokir alamat IP {src_ip} secara otomatis pada router "
        "selama {durasi_blokir} menit. Pantau apakah aktivitas serupa berulang "
        "setelah blokir dicabut."
    ),
    STATUS_MENUNGGU: (
        "Pemblokiran alamat IP {src_ip} menunggu persetujuan administrator. "
        "Tinjau rasio serangan dan confidence setiap sumber sebelum menyetujui "
        "atau menolak."
    ),
    STATUS_DICATAT: (
        "Insiden ini hanya dicatat karena tidak ada sumber yang memenuhi gerbang "
        "rasio serangan dan confidence. Pemblokiran tidak disarankan; pantau "
        "alamat IP {src_ip} bila aktivitas berlanjut."
    ),
    STATUS_DISETUJUI: (
        "Administrator menyetujui pemblokiran alamat IP {src_ip} selama "
        "{durasi_blokir} menit."
    ),
    STATUS_DITOLAK: (
        "Administrator menolak pemblokiran alamat IP {src_ip}. Insiden tetap "
        "tercatat tanpa perubahan pada router."
    ),
}

TAMBAHAN_SCANNING = (
    " Tinjau juga log akses pada {dst_ip} untuk memastikan tidak ada layanan "
    "yang berhasil diakses selama pemindaian."
)


def tindakan_untuk_status(kelas, status, src_ip, dst_ip, durasi_blokir=15):
    """Kalimat tindakan yang konsisten dengan status keputusan mitigasi."""
    teks = TINDAKAN_STATUS[status].format(src_ip=src_ip, durasi_blokir=durasi_blokir)
    if kelas == "port_scanning" and status in (STATUS_BLOKIR_OTOMATIS, STATUS_DISETUJUI):
        teks += TAMBAHAN_SCANNING.format(dst_ip=dst_ip)
    return teks


def terapkan_status(saran, status, durasi_blokir=None):
    """
    Memperbarui saran yang sudah ada setelah status insiden berubah
    (pemutus darurat, disetujui, ditolak). Mengubah dict di tempat dan
    mengembalikannya.
    """
    if not saran or saran.get("kelas") not in TEMPLATE:
        return saran
    durasi = durasi_blokir if durasi_blokir is not None else saran.get("durasi_blokir", 15)
    tindakan = tindakan_untuk_status(
        saran["kelas"], status, saran.get("src_ip", "-"), saran.get("dst_ip", "-"), durasi
    )
    saran["saran_mitigasi"] = tindakan
    saran["narasi"] = f"{saran['deskripsi']}\n\n{saran['dampak']}\n\n{tindakan}"
    saran["mitigasi_otomatis"] = status == STATUS_BLOKIR_OTOMATIS
    saran["status"] = status
    return saran


def susun_saran(
    kelas,
    src_ip,
    dst_ip,
    confidence,
    packet_count=0,
    byte_count=0,
    flow_rate=0.0,
    dst_port_count=0,
    waktu=None,
    durasi_blokir=15,
    ambang_tinggi=AMBANG_TINGGI,
    ambang_sedang=AMBANG_SEDANG,
    status=None,
):
    """
    Menyusun narasi saran tindakan untuk satu hasil deteksi.

    Parameter
    ---------
    kelas : str
        Hasil klasifikasi model: 'normal', 'ddos_flood', atau 'port_scanning'
    src_ip, dst_ip : str
        Alamat IP sumber dan tujuan dari flow yang terdeteksi
    confidence : float
        Tingkat kepercayaan klasifikasi, rentang 0 sampai 1
    durasi_blokir : int
        Usulan lama pemblokiran dalam menit
    ambang_tinggi, ambang_sedang : float
        Ambang kepercayaan; default AMBANG_TINGGI / AMBANG_SEDANG
    status : str | None
        Status keputusan mitigasi insiden. Bila diisi, kalimat tindakan
        mengikuti status ini (TINDAKAN_STATUS) dan mitigasi_otomatis True
        hanya untuk blokir_otomatis. Bila None (uji satu flow), tindakan
        mengikuti confidence dan tidak pernah berupa pemblokiran yang sudah
        dijalankan.

    Mengembalikan dict berisi judul, tingkat risiko, narasi, dan flag
    apakah mitigasi otomatis disarankan.
    """
    if kelas == "normal":
        return {
            "kelas": "normal",
            "judul": "Trafik Normal",
            "tingkat": "Aman",
            "narasi": "Tidak terdeteksi indikasi serangan pada trafik ini.",
            "saran_mitigasi": None,
            "mitigasi_otomatis": False,
            "confidence": confidence,
        }

    if kelas not in TEMPLATE:
        return {
            "kelas": kelas,
            "judul": "Klasifikasi Tidak Dikenali",
            "tingkat": "Tidak diketahui",
            "narasi": f"Model mengembalikan kelas '{kelas}' yang tidak memiliki template narasi.",
            "saran_mitigasi": None,
            "mitigasi_otomatis": False,
            "confidence": confidence,
        }

    t = TEMPLATE[kelas]
    waktu = waktu or datetime.now().strftime("%d-%m-%Y %H:%M:%S")

    konteks = {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "waktu": waktu,
        "packet_count": packet_count,
        "byte_count": byte_count,
        "flow_rate": flow_rate,
        "dst_port_count": dst_port_count,
        "durasi_blokir": durasi_blokir,
    }

    deskripsi = t["deskripsi"].format(**konteks)
    dampak = t["dampak"].format(**konteks)

    # Tingkat kepercayaan menentukan apakah sistem menyarankan mitigasi
    # otomatis atau cukup pemantauan. Ini mengurangi risiko pemblokiran
    # alamat IP yang sebenarnya sah.
    if status is not None:
        tindakan = tindakan_untuk_status(kelas, status, src_ip, dst_ip, durasi_blokir)
        otomatis = status == STATUS_BLOKIR_OTOMATIS
    elif confidence >= ambang_tinggi:
        tindakan = t["tindakan_tinggi"].format(**konteks)
        otomatis = True
    elif confidence >= ambang_sedang:
        tindakan = t["tindakan_sedang"].format(**konteks)
        otomatis = False
    else:
        tindakan = (
            f"Tingkat kepercayaan klasifikasi rendah ({confidence:.1%}). "
            f"Disarankan verifikasi manual sebelum mengambil tindakan apa pun "
            f"terhadap alamat IP {src_ip}."
        )
        otomatis = False

    narasi = f"{deskripsi}\n\n{dampak}\n\n{tindakan}"

    return {
        "kelas": kelas,
        "judul": t["judul"],
        "tingkat": t["tingkat"],
        "narasi": narasi,
        "deskripsi": deskripsi,
        "dampak": dampak,
        "saran_mitigasi": tindakan,
        "mitigasi_otomatis": otomatis,
        "confidence": confidence,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "waktu": waktu,
        "durasi_blokir": durasi_blokir,
        "status": status,
    }


if __name__ == "__main__":
    # Contoh penggunaan untuk pengujian manual
    contoh = [
        dict(
            kelas="ddos_flood",
            src_ip="192.168.20.10",
            dst_ip="192.168.30.10",
            confidence=0.97,
            packet_count=4820,
            byte_count=289200,
            flow_rate=2410.0,
        ),
        dict(
            kelas="port_scanning",
            src_ip="192.168.20.10",
            dst_ip="192.168.30.10",
            confidence=0.83,
            dst_port_count=412,
        ),
        dict(
            kelas="normal",
            src_ip="192.168.10.10",
            dst_ip="192.168.30.10",
            confidence=0.99,
        ),
    ]

    for c in contoh:
        hasil = susun_saran(**c)
        print("=" * 70)
        print(f"{hasil['judul']}  [Tingkat: {hasil['tingkat']}]")
        print(f"Kepercayaan: {hasil['confidence']:.1%}")
        print(f"Mitigasi otomatis: {'Ya' if hasil['mitigasi_otomatis'] else 'Tidak'}")
        print("-" * 70)
        print(hasil["narasi"])
        print()
