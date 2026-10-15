"""
mitigasi.py
===========
Modul mitigasi otomatis: memblokir alamat IP sumber serangan pada router
melalui koneksi SSH menggunakan library Netmiko.

Modul ini bersifat deterministik dan berbasis aturan. Model machine learning
hanya bertugas melakukan klasifikasi; keputusan pemblokiran dieksekusi oleh
modul ini berdasarkan hasil klasifikasi tersebut. Pemisahan ini disengaja
agar tindakan yang berdampak langsung pada jaringan dapat diaudit.

Catatan platform:
    Implementasi ini menargetkan VyOS (device_type 'vyos'). Bila penelitian
    kembali menggunakan Cisco IOS, ubah DEVICE_TYPE menjadi 'cisco_ios' dan
    gunakan kumpulan perintah pada CISCO_COMMANDS.
"""

import logging
from datetime import datetime, timedelta

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("mitigasi")

DEVICE_TYPE = "vyos"

# Nama firewall group pada VyOS yang menampung daftar IP terblokir
FIREWALL_GROUP = "BLOKIR_NDR"


class ModulMitigasi:
    """
    Mengelola koneksi ke router dan penerapan aturan pemblokiran.

    Daftar IP yang sedang diblokir disimpan di memori beserta waktu
    kedaluwarsanya, sehingga pencabutan otomatis dapat dilakukan.
    """

    def __init__(self, host, username, password, port=22, dry_run=False):
        """
        Parameter
        ---------
        dry_run : bool
            Bila True, perintah hanya dicatat di log tanpa benar-benar
            dikirim ke router. Berguna untuk pengujian tanpa risiko.
        """
        self.host = host
        self.username = username
        self.password = password
        self.port = port
        self.dry_run = dry_run
        self.terblokir = {}  # {ip: waktu_kedaluwarsa}

    # ------------------------------------------------------------- koneksi

    def _koneksi(self):
        """Membuka koneksi SSH ke router."""
        if self.dry_run:
            return None

        try:
            from netmiko import ConnectHandler
        except ImportError:
            raise RuntimeError("Netmiko belum terpasang. Jalankan: pip install netmiko")

        return ConnectHandler(
            device_type=DEVICE_TYPE,
            host=self.host,
            username=self.username,
            password=self.password,
            port=self.port,
            timeout=20,
        )

    def _jalankan(self, perintah_list, deskripsi):
        """
        Mengirim sekumpulan perintah konfigurasi ke router.

        Mengembalikan True bila berhasil, False bila gagal. Kegagalan
        dicatat di log tetapi tidak menghentikan program, karena sistem
        deteksi harus tetap berjalan meski mitigasi gagal.
        """
        if self.dry_run:
            log.info(f"[DRY RUN] {deskripsi}")
            for p in perintah_list:
                log.info(f"[DRY RUN]   {p}")
            return True

        koneksi = None
        try:
            koneksi = self._koneksi()
            hasil = koneksi.send_config_set(perintah_list, exit_config_mode=False)
            koneksi.send_command("commit", expect_string=r"#")
            koneksi.send_command("save", expect_string=r"#")
            koneksi.send_command("exit", expect_string=r"[$#]")
            log.info(f"Berhasil: {deskripsi}")
            log.debug(hasil)
            return True

        except Exception as e:
            log.error(f"Gagal {deskripsi}: {e}")
            return False

        finally:
            if koneksi:
                try:
                    koneksi.disconnect()
                except Exception:
                    pass

    # ------------------------------------------------------------ persiapan

    def siapkan_firewall(self, interface="eth1"):
        """
        Menyiapkan struktur firewall di router.

        Perlu dijalankan sekali saja sebelum sistem mulai beroperasi.
        Membuat address-group kosong dan aturan yang menolak trafik dari
        anggota group tersebut.
        """
        perintah = [
            f"set firewall group address-group {FIREWALL_GROUP} description 'IP diblokir sistem NDR'",
            f"set firewall ipv4 input filter rule 10 action drop",
            f"set firewall ipv4 input filter rule 10 source group address-group {FIREWALL_GROUP}",
            f"set firewall ipv4 forward filter rule 10 action drop",
            f"set firewall ipv4 forward filter rule 10 source group address-group {FIREWALL_GROUP}",
        ]
        return self._jalankan(perintah, "menyiapkan struktur firewall")

    # ------------------------------------------------------------- mitigasi

    def blokir(self, ip, durasi_menit=15, alasan=""):
        """
        Memblokir satu alamat IP selama durasi tertentu.

        Pemblokiran bersifat sementara. Waktu kedaluwarsa dicatat agar
        modul dapat mencabutnya secara otomatis melalui cabut_kedaluwarsa().
        """
        if ip in self.terblokir:
            log.info(f"{ip} sudah dalam daftar blokir, memperpanjang durasi")

        perintah = [
            f"set firewall group address-group {FIREWALL_GROUP} address {ip}",
        ]

        deskripsi = f"memblokir {ip} selama {durasi_menit} menit"
        if alasan:
            deskripsi += f" ({alasan})"

        berhasil = self._jalankan(perintah, deskripsi)

        if berhasil:
            self.terblokir[ip] = datetime.now() + timedelta(minutes=durasi_menit)

        return berhasil

    def cabut(self, ip):
        """Mencabut pemblokiran satu alamat IP."""
        perintah = [
            f"delete firewall group address-group {FIREWALL_GROUP} address {ip}",
        ]

        berhasil = self._jalankan(perintah, f"mencabut blokir {ip}")

        if berhasil:
            self.terblokir.pop(ip, None)

        return berhasil

    def cabut_kedaluwarsa(self):
        """
        Mencabut seluruh pemblokiran yang sudah melewati waktu kedaluwarsa.

        Dipanggil secara berkala oleh backend, misalnya setiap satu menit.
        Mengembalikan daftar IP yang berhasil dicabut.
        """
        sekarang = datetime.now()
        kedaluwarsa = [ip for ip, waktu in self.terblokir.items() if waktu <= sekarang]

        dicabut = []
        for ip in kedaluwarsa:
            if self.cabut(ip):
                dicabut.append(ip)
                log.info(f"Blokir {ip} dicabut otomatis karena kedaluwarsa")

        return dicabut

    def daftar_terblokir(self):
        """Mengembalikan daftar IP terblokir beserta sisa waktunya."""
        sekarang = datetime.now()
        hasil = []
        for ip, kedaluwarsa in self.terblokir.items():
            sisa = (kedaluwarsa - sekarang).total_seconds()
            hasil.append(
                {
                    "ip": ip,
                    "kedaluwarsa": kedaluwarsa.isoformat(),
                    "sisa_detik": max(0, int(sisa)),
                }
            )
        return hasil

    # ------------------------------------------------------------ verifikasi

    def uji_koneksi(self):
        """Menguji apakah router dapat dijangkau melalui SSH."""
        if self.dry_run:
            log.info("[DRY RUN] Uji koneksi dilewati")
            return True

        try:
            koneksi = self._koneksi()
            hasil = koneksi.send_command("show version")
            koneksi.disconnect()
            log.info(f"Koneksi ke {self.host} berhasil")
            return True
        except Exception as e:
            log.error(f"Koneksi ke {self.host} gagal: {e}")
            return False


# ---------------------------------------------------------- perintah Cisco

# Disimpan sebagai referensi bila penelitian kembali menggunakan Cisco IOS.
# Untuk memakainya, ubah DEVICE_TYPE menjadi 'cisco_ios' dan sesuaikan
# metode blokir() serta cabut() agar menggunakan perintah di bawah ini.
CISCO_COMMANDS = {
    "blokir": [
        "ip access-list extended BLOKIR_NDR",
        " deny ip host {ip} any",
        " permit ip any any",
    ],
    "cabut": [
        "ip access-list extended BLOKIR_NDR",
        " no deny ip host {ip} any",
    ],
}


if __name__ == "__main__":
    # Pengujian dalam mode dry run, tidak mengirim apa pun ke router
    print("Uji modul mitigasi dalam mode DRY RUN\n")

    m = ModulMitigasi(
        host="192.168.10.1",
        username="vyos",
        password="vyos",
        dry_run=True,
    )

    m.uji_koneksi()
    print()
    m.siapkan_firewall()
    print()
    m.blokir("192.168.20.10", durasi_menit=15, alasan="DDoS Flood")
    print()
    m.blokir("192.168.20.55", durasi_menit=5, alasan="Port Scanning")
    print()

    print("Daftar IP terblokir:")
    for entri in m.daftar_terblokir():
        print(f"  {entri['ip']}  sisa {entri['sisa_detik']} detik")
    print()

    m.cabut("192.168.20.10")
