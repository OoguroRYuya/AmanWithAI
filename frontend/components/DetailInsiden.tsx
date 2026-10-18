"use client";

import { useEffect, useRef } from "react";

import { fAngka, fDetik, fJam, fPersen } from "@/lib/format";
import type { Insiden } from "@/lib/tipe";

import { LencanaKelas, LencanaStatus } from "./Lencana";

interface Props {
  insiden: Insiden;
  onTutup: () => void;
  onSetujui: (id: number) => Promise<boolean>;
  onTolak: (id: number) => Promise<boolean>;
}

export default function DetailInsiden({ insiden: i, onTutup, onSetujui, onTolak }: Props) {
  const dialog = useRef<HTMLDialogElement>(null);

  useEffect(() => {
    const d = dialog.current;
    if (d && !d.open) d.showModal();
  }, []);

  // Evaluasi sumber: yang lolos dulu, lalu rasio tertinggi
  const evals = [...i.evaluasi_sumber].sort(
    (a, b) => Number(b.lolos) - Number(a.lolos) || b.rasio_serangan - a.rasio_serangan,
  );
  const menunggu = i.status === "menunggu_persetujuan";

  return (
    <dialog
      ref={dialog}
      className="panel-detail"
      onClose={onTutup}
      onClick={(e) => e.target === dialog.current && dialog.current?.close()}
    >
      <div className="panel-isi">
        <div className="panel-kepala">
          <div>
            <h2>
              Insiden #{i.id} · {i.saran?.judul ?? i.kelas}
            </h2>
            <div className="baris-lencana">
              <LencanaKelas kelas={i.kelas} />
              <LencanaStatus status={i.status} />
              {i.saran?.tingkat && <span className="lencana">Risiko: {i.saran.tingkat}</span>}
            </div>
          </div>
          <button className="tombol-teks" onClick={() => dialog.current?.close()} aria-label="Tutup">
            ✕
          </button>
        </div>

        <dl className="fakta">
          <div>
            <dt>Jendela</dt>
            <dd>{i.window.replace("T", " ")}</dd>
          </div>
          <div>
            <dt>Kunci</dt>
            <dd className="mono">{i.kunci}</dd>
          </div>
          <div>
            <dt>Tujuan</dt>
            <dd className="mono">{i.tujuan.join(", ")}</dd>
          </div>
          <div>
            <dt>Flow / sumber</dt>
            <dd>
              {fAngka(i.jumlah_flow)} / {fAngka(i.jumlah_sumber)}
            </dd>
          </div>
          <div>
            <dt>Confidence insiden</dt>
            <dd>{fPersen(i.confidence)}</dd>
          </div>
          <div>
            <dt>Keputusan</dt>
            <dd>{i.alasan}</dd>
          </div>
          <div>
            <dt>IP diblokir</dt>
            <dd>{fAngka(i.ip_blokir.length)}</dd>
          </div>
          <div>
            <dt>IP kandidat</dt>
            <dd>{fAngka(i.ip_kandidat.length)}</dd>
          </div>
        </dl>

        {menunggu && (
          <div className="aksi-persetujuan">
            <span>Blokir {fAngka(i.ip_kandidat.length)} IP kandidat?</span>
            <button className="tombol utama" onClick={() => onSetujui(i.id)}>
              Setujui
            </button>
            <button className="tombol" onClick={() => onTolak(i.id)}>
              Tolak
            </button>
          </div>
        )}

        <h3>Narasi saran tindakan</h3>
        <div className="narasi">{i.saran?.narasi ?? "–"}</div>

        <h3>Latensi</h3>
        <dl className="fakta">
          <div>
            <dt>Deteksi</dt>
            <dd>{fDetik(i.latensi_detik?.deteksi)}</dd>
          </div>
          <div>
            <dt>Mitigasi</dt>
            <dd>{fDetik(i.latensi_detik?.mitigasi)}</dd>
          </div>
          <div>
            <dt>Akhir jendela</dt>
            <dd>{fJam(i.t_window_end, true)}</dd>
          </div>
          <div>
            <dt>Diterima</dt>
            <dd>{fJam(i.t_diterima, true)}</dd>
          </div>
          <div>
            <dt>Diklasifikasi</dt>
            <dd>{fJam(i.t_klasifikasi, true)}</dd>
          </div>
          <div>
            <dt>Dimitigasi</dt>
            <dd>{fJam(i.t_mitigasi, true)}</dd>
          </div>
        </dl>

        <h3>Evaluasi sumber ({fAngka(evals.length)})</h3>
        <div className="gulir tabel-evaluasi">
          <table>
            <thead>
              <tr>
                <th>IP sumber</th>
                <th className="angka">Rasio serangan</th>
                <th className="angka">Conf. rata-rata</th>
                <th>Lolos</th>
                <th>Alasan</th>
              </tr>
            </thead>
            <tbody>
              {evals.map((e) => (
                <tr key={e.ip}>
                  <td className="mono">{e.ip}</td>
                  <td className="angka">{fPersen(e.rasio_serangan)}</td>
                  <td className="angka">{fPersen(e.conf_rata)}</td>
                  <td>{e.lolos ? "✓ ya" : "✕ tidak"}</td>
                  <td className="redup">{e.alasan}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </dialog>
  );
}
