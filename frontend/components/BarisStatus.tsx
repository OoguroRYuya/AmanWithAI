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
}

export default function BarisStatus({ status, koneksi, pesanTerakhir, jumlahMenunggu, jumlahTerblokir }: Props) {
  const dryRun = status?.dry_run ?? true;
  return (
    <header className="baris-status">
      <div className="judul-app">
        <h1>NDR Kampus</h1>
        <span className="sub">Deteksi &amp; mitigasi serangan jaringan</span>
      </div>

      <div className={`mode ${dryRun ? "mode-dry" : "mode-aktif"}`} role="status">
        <strong>{dryRun ? "DRY RUN" : "AKTIF"}</strong>
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
          <dt>Ambang</dt>
          <dd className="ambang">
            rasio ≥ {status?.ambang_rasio_serangan?.toFixed(2) ?? "–"} · blokir ≥{" "}
            {status?.ambang_conf_blokir?.toFixed(2) ?? "–"} · setuju ≥ {status?.ambang_sedang?.toFixed(2) ?? "–"}
          </dd>
        </div>
        <div>
          <dt>WebSocket</dt>
          <dd className={`koneksi koneksi-${koneksi}`}>
            <span className="titik" aria-hidden />
            {LABEL_KONEKSI[koneksi]}
            {pesanTerakhir && koneksi === "tersambung" && (
              <span className="redup" title="Pesan terakhir diterima">
                {" "}· {new Date(pesanTerakhir).toLocaleTimeString("id-ID")}
              </span>
            )}
          </dd>
        </div>
      </dl>
    </header>
  );
}
