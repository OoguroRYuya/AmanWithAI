import { fAngka } from "@/lib/format";
import type { KoneksiWS, StatusSistem } from "@/lib/tipe";

const LABEL_KONEKSI: Record<KoneksiWS, string> = {
  tersambung: "Tersambung",
  menyambung: "Menyambung…",
  terputus: "Terputus, mencoba lagi…",
};

interface Props {
  status: StatusSistem | null;
  koneksi: KoneksiWS;
  pesanTerakhir: number | null;
  jumlahMenunggu: number;
  jumlahTerblokir: number;
  onKeluar: () => void;
}

export default function BarisStatus({
  status,
  koneksi,
  pesanTerakhir,
  jumlahMenunggu,
  jumlahTerblokir,
  onKeluar,
}: Props) {
  const dryRun = status?.dry_run ?? true;
  return (
    <header className="baris-status">
      <div className="judul-app">
        <h1>NDR Kampus</h1>
        <span className="sub">Deteksi &amp; mitigasi serangan jaringan</span>
      </div>

      <div className={`mode ${dryRun ? "mode-dry" : "mode-aktif"}`} role="status">
        <strong>{dryRun ? "Dry run" : "Aktif"}</strong>
        <span>{dryRun ? "perintah tidak dikirim ke router" : "memblokir langsung di router"}</span>
      </div>

      <dl className="ringkas">
        <div>
          <dt>Model</dt>
          <dd>{status ? (status.model_dimuat ? "✓ dimuat" : "✕ belum dimuat") : "–"}</dd>
        </div>
        <div>
          <dt>Sumber data</dt>
          <dd>{status?.sumber_data ?? "–"}</dd>
        </div>
        <div>
          <dt>IP terblokir</dt>
          <dd>{fAngka(jumlahTerblokir)}</dd>
        </div>
        <div>
          <dt>Menunggu persetujuan</dt>
          <dd>{fAngka(jumlahMenunggu)}</dd>
        </div>
        <div>
          <dt>WebSocket</dt>
          <dd className={`koneksi koneksi-${koneksi}`}>
            {/* titik = keadaan koneksi saat ini (bukan dekorasi) */}
            <span className="titik" aria-hidden />
            {LABEL_KONEKSI[koneksi]}
            {pesanTerakhir && koneksi === "tersambung" && (
              <time className="waktu-pesan" title="Pesan terakhir diterima">
                {new Date(pesanTerakhir).toLocaleTimeString("id-ID")}
              </time>
            )}
          </dd>
        </div>
      </dl>

      <button type="button" className="tombol kecil" onClick={onKeluar}>
        Keluar
      </button>
    </header>
  );
}
