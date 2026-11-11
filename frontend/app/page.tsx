"use client";

import { useCallback, useEffect, useMemo, useState } from "react";

import AntreanPersetujuan from "@/components/AntreanPersetujuan";
import BarisStatus from "@/components/BarisStatus";
import DaftarTerblokir from "@/components/DaftarTerblokir";
import DetailInsiden from "@/components/DetailInsiden";
import GrafikTrafik from "@/components/GrafikTrafik";
import Masuk from "@/components/Masuk";
import TabelInsiden from "@/components/TabelInsiden";
import * as api from "@/lib/api";
import { useDashboard } from "@/lib/useDashboard";

type Sesi = { t: "memeriksa" } | { t: "galat"; pesan: string } | { t: "keluar"; dikonfigurasi: boolean } | { t: "masuk" };

// Dashboard (dan WebSocket-nya) hanya dipasang selama sesi admin valid;
// saat sesi habis atau admin keluar, komponennya dilepas dan WS ditutup.
export default function Halaman() {
  const [sesi, setSesi] = useState<Sesi>({ t: "memeriksa" });

  const periksa = useCallback(() => {
    setSesi({ t: "memeriksa" });
    api
      .cekSesi()
      .then((s) => setSesi(s.masuk ? { t: "masuk" } : { t: "keluar", dikonfigurasi: s.dikonfigurasi }))
      .catch((e: Error) => setSesi({ t: "galat", pesan: e.message }));
  }, []);

  useEffect(() => {
    periksa();
    window.addEventListener(api.EVENT_SESI_HABIS, periksa);
    return () => window.removeEventListener(api.EVENT_SESI_HABIS, periksa);
  }, [periksa]);

  const keluar = useCallback(() => {
    api.keluar().finally(periksa);
  }, [periksa]);

  switch (sesi.t) {
    case "memeriksa":
      return <main className="layar-masuk kosong">Memeriksa sesi…</main>;
    case "galat":
      return (
        <main className="layar-masuk">
          <div className="kartu kartu-masuk" role="alert">
            <h1>Backend tidak dapat dihubungi</h1>
            <p className="redup">{sesi.pesan}</p>
            <button className="tombol" onClick={periksa}>
              Coba lagi
            </button>
          </div>
        </main>
      );
    case "keluar":
      return <Masuk dikonfigurasi={sesi.dikonfigurasi} onBerhasil={periksa} />;
    case "masuk":
      return <Dashboard onKeluar={keluar} />;
  }
}

function Dashboard({ onKeluar }: { onKeluar: () => void }) {
  const { keadaan, toasts, aksi } = useDashboard();
  const [dipilih, setDipilih] = useState<number | null>(null);

  const insiden = useMemo(() => Object.values(keadaan.insiden).sort((a, b) => b.id - a.id), [keadaan.insiden]);
  // Antrean diturunkan dari insiden, jadi insiden yang dikirim ulang dengan
  // status disetujui/ditolak otomatis keluar dari antrean
  const menunggu = useMemo(
    () => insiden.filter((i) => i.status === "menunggu_persetujuan").sort((a, b) => a.id - b.id),
    [insiden],
  );
  // Panel detail mengikuti versi terbaru insiden yang sama
  const insidenDipilih = dipilih != null ? keadaan.insiden[dipilih] : undefined;
  const s = keadaan.status;

  return (
    <main className="halaman">
      <BarisStatus
        status={s}
        koneksi={keadaan.koneksi}
        pesanTerakhir={keadaan.pesanTerakhir}
        jumlahMenunggu={menunggu.length}
        jumlahTerblokir={keadaan.terblokir.length}
        onKeluar={onKeluar}
      />

      <GrafikTrafik trafik={keadaan.trafik} />

      <div className="dua-kolom">
        <AntreanPersetujuan
          menunggu={menunggu}
          ambangSedang={s?.ambang_sedang}
          ambangBlokir={s?.ambang_conf_blokir}
          onSetujui={aksi.setujui}
          onTolak={aksi.tolak}
          onPilih={setDipilih}
        />
        <DaftarTerblokir
          terblokir={keadaan.terblokir}
          terblokirPada={keadaan.terblokirPada}
          allowlist={s?.allowlist}
          onCabut={aksi.cabut}
          onBlokir={aksi.blokir}
        />
      </div>

      <TabelInsiden insiden={insiden} onPilih={setDipilih} />

      {insidenDipilih && (
        <DetailInsiden
          key={insidenDipilih.id}
          insiden={insidenDipilih}
          onTutup={() => setDipilih(null)}
          onSetujui={aksi.setujui}
          onTolak={aksi.tolak}
        />
      )}

      <div className="toasts" aria-live="polite">
        {toasts.map((t) => (
          <div key={t.id} className={`toast toast-${t.jenis}`}>
            {t.teks}
          </div>
        ))}
      </div>
    </main>
  );
}
