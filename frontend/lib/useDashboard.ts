"use client";

import { useCallback, useEffect, useReducer, useRef, useState } from "react";

import * as api from "./api";
import type { Insiden, KoneksiWS, PesanWS, StatusSistem, Terblokir, Trafik } from "./tipe";

const MAKS_TRAFIK = 60;
const MAKS_INSIDEN = 500; // sama dengan MAKS_RIWAYAT backend
const JEDA_MAKS_MS = 30_000;
// Server mengirim ping tiap 20 detik; bila lebih lama dari ini tanpa pesan
// apa pun, koneksi dianggap mati walau socket belum menutup.
const BATAS_HENING_MS = 60_000;

export interface Keadaan {
  status: StatusSistem | null;
  insiden: Record<number, Insiden>;
  trafik: Record<string, Trafik>;
  terblokir: Terblokir[];
  // waktu lokal saat `terblokir` diterima; dasar hitung mundur sisa_detik
  terblokirPada: number;
  koneksi: KoneksiWS;
  pesanTerakhir: number | null;
}

type Aksi =
  | { t: "rest"; status: StatusSistem; insiden: Insiden[]; trafik: Trafik[]; terblokir: Terblokir[] }
  | { t: "snapshot"; status: StatusSistem; insiden: Insiden[]; trafik: Trafik[]; terblokir: Terblokir[] }
  | { t: "insiden"; data: Insiden[] }
  | { t: "trafik"; data: Trafik }
  | { t: "status"; data: Partial<StatusSistem> }
  | { t: "terblokir"; data: Terblokir[] }
  | { t: "koneksi"; data: KoneksiWS }
  | { t: "pesan" };

const awal: Keadaan = {
  status: null,
  insiden: {},
  trafik: {},
  terblokir: [],
  terblokirPada: 0,
  koneksi: "menyambung",
  pesanTerakhir: null,
};

// Upsert insiden berdasarkan id: snapshot dan stream bisa mengirim insiden
// yang sama, dan insiden dikirim ulang saat statusnya berubah.
function upsertInsiden(lama: Record<number, Insiden>, baru: Insiden[]) {
  if (!baru.length) return lama;
  const hasil = { ...lama };
  for (const i of baru) hasil[i.id] = i;
  const ids = Object.keys(hasil).map(Number);
  if (ids.length > MAKS_INSIDEN) {
    ids.sort((a, b) => a - b);
    for (const id of ids.slice(0, ids.length - MAKS_INSIDEN)) delete hasil[id];
  }
  return hasil;
}

// Upsert trafik berdasarkan window, simpan MAKS_TRAFIK jendela terakhir
function upsertTrafik(lama: Record<string, Trafik>, baru: Trafik[]) {
  if (!baru.length) return lama;
  const hasil = { ...lama };
  for (const t of baru) hasil[t.window] = t;
  const kunci = Object.keys(hasil).sort();
  for (const k of kunci.slice(0, Math.max(0, kunci.length - MAKS_TRAFIK))) delete hasil[k];
  return hasil;
}

function bersihkan<T extends { tipe: string }>(p: T): Omit<T, "tipe"> {
  const { tipe: _, ...sisa } = p;
  return sisa;
}

function reducer(s: Keadaan, a: Aksi): Keadaan {
  switch (a.t) {
    // REST memuat seluruh riwayat backend, jadi menggantikan isi lokal: bila
    // backend dijalankan ulang, id insiden mulai lagi dari 1 dan insiden lama
    // tidak boleh tercampur. Snapshot hanya 50 insiden terbaru -> upsert.
    case "rest":
      return {
        ...s,
        status: a.status,
        insiden: upsertInsiden({}, a.insiden),
        trafik: upsertTrafik({}, a.trafik),
        terblokir: a.terblokir,
        terblokirPada: Date.now(),
      };
    case "snapshot":
      return {
        ...s,
        status: a.status,
        insiden: upsertInsiden(s.insiden, a.insiden),
        trafik: upsertTrafik(s.trafik, a.trafik),
        terblokir: a.terblokir,
        terblokirPada: Date.now(),
      };
    case "insiden":
      return { ...s, insiden: upsertInsiden(s.insiden, a.data) };
    case "trafik":
      return { ...s, trafik: upsertTrafik(s.trafik, [a.data]) };
    case "status":
      return { ...s, status: { ...(s.status ?? ({} as StatusSistem)), ...a.data } };
    case "terblokir":
      return { ...s, terblokir: a.data, terblokirPada: Date.now() };
    case "koneksi":
      return { ...s, koneksi: a.data };
    case "pesan":
      return { ...s, pesanTerakhir: Date.now() };
  }
}

export interface Toast {
  id: number;
  jenis: "info" | "sukses" | "galat";
  teks: string;
}

export function useDashboard() {
  const [keadaan, dispatch] = useReducer(reducer, awal);
  const [toasts, setToasts] = useState<Toast[]>([]);
  const nomorToast = useRef(0);
  // Nomor urut permintaan /api/terblokir: jawaban lama yang tiba belakangan
  // tidak boleh menimpa jawaban yang lebih baru
  const nomorTerblokir = useRef(0);
  // Pesan insiden/trafik dari WS yang tiba selama REST sedang dimuat;
  // diterapkan ulang setelah REST menggantikan isi lokal agar tidak hilang
  const penyangga = useRef<{ insiden: Insiden[]; trafik: Trafik[] } | null>(null);

  const toast = useCallback((jenis: Toast["jenis"], teks: string) => {
    const id = ++nomorToast.current;
    setToasts((t) => [...t.slice(-3), { id, jenis, teks }]);
    setTimeout(() => setToasts((t) => t.filter((x) => x.id !== id)), 4500);
  }, []);

  const muatTerblokir = useCallback(async () => {
    const nomor = ++nomorTerblokir.current;
    try {
      const data = await api.ambilTerblokir();
      if (nomor === nomorTerblokir.current) dispatch({ t: "terblokir", data });
    } catch {
      /* dicoba lagi pada pesan mitigasi berikutnya */
    }
  }, []);

  const muatRest = useCallback(async () => {
    const buf = { insiden: [] as Insiden[], trafik: [] as Trafik[] };
    penyangga.current = buf;
    try {
      const [status, trafik, insiden, persetujuan, terblokir] = await Promise.all([
        api.ambilStatus(),
        api.ambilTrafik(MAKS_TRAFIK),
        api.ambilInsiden(MAKS_INSIDEN),
        // antrean persetujuan bisa berisi insiden yang lebih tua dari 500 terakhir
        api.ambilPersetujuan(),
        api.ambilTerblokir(),
      ]);
      dispatch({
        t: "rest",
        status,
        trafik: [...trafik, ...buf.trafik],
        insiden: [...persetujuan, ...insiden, ...buf.insiden],
        terblokir,
      });
    } finally {
      if (penyangga.current === buf) penyangga.current = null;
    }
  }, []);

  useEffect(() => {
    let berhenti = false;
    let ws: WebSocket | null = null;
    let timerSambung: ReturnType<typeof setTimeout> | undefined;
    let percobaan = 0;
    let restSiap = false;
    let pernahTersambung = false;
    let terakhir = Date.now();

    const tangani = (p: PesanWS) => {
      terakhir = Date.now();
      dispatch({ t: "pesan" });
      switch (p.tipe) {
        case "snapshot":
          dispatch({ t: "snapshot", status: p.status, insiden: p.insiden, trafik: p.trafik, terblokir: p.terblokir });
          break;
        case "trafik": {
          const t = bersihkan(p);
          penyangga.current?.trafik.push(t);
          dispatch({ t: "trafik", data: t });
          break;
        }
        case "insiden": {
          const i = bersihkan(p) as Insiden;
          penyangga.current?.insiden.push(i);
          dispatch({ t: "insiden", data: [i] });
          break;
        }
        case "status":
          dispatch({ t: "status", data: bersihkan(p) });
          break;
        case "mitigasi": {
          const aksi = p.aksi === "blokir" ? "Blokir" : "Cabut blokir";
          const jumlah = p.ip.length === 1 ? p.ip[0] : `${p.ip.length} IP`;
          toast("info", `${aksi} ${p.oleh}: ${jumlah}${p.dry_run ? " (dry run)" : ""}`);
          void muatTerblokir();
          break;
        }
        case "ping":
          break;
      }
    };

    const sambung = () => {
      if (berhenti) return;
      dispatch({ t: "koneksi", data: "menyambung" });
      const soket = new WebSocket(api.WS_URL);
      ws = soket;
      soket.onopen = () => {
        percobaan = 0;
        terakhir = Date.now();
        dispatch({ t: "koneksi", data: "tersambung" });
        // Snapshot hanya memuat 50 insiden terbaru; setelah tersambung ulang
        // (atau bila REST awal gagal) muat ulang REST agar status insiden
        // yang lebih lama ikut sinkron.
        if (pernahTersambung || !restSiap) {
          muatRest().then(() => (restSiap = true)).catch(() => undefined);
        }
        pernahTersambung = true;
      };
      soket.onmessage = (e) => {
        try {
          tangani(JSON.parse(e.data) as PesanWS);
        } catch (err) {
          console.error("Pesan WS tidak valid", err);
        }
      };
      soket.onerror = () => soket.close();
      soket.onclose = () => {
        if (berhenti || ws !== soket) return;
        dispatch({ t: "koneksi", data: "terputus" });
        // backoff eksponensial 1s, 2s, 4s, ... maks 30s, dengan sedikit acak
        const jeda = Math.min(JEDA_MAKS_MS, 1000 * 2 ** percobaan) + Math.random() * 500;
        percobaan += 1;
        timerSambung = setTimeout(sambung, jeda);
      };
    };

    const pengawas = setInterval(() => {
      if (ws?.readyState === WebSocket.OPEN && Date.now() - terakhir > BATAS_HENING_MS) {
        ws.close();
      }
    }, 10_000);

    muatRest()
      .then(() => (restSiap = true))
      .catch((e) => toast("galat", `Gagal memuat data awal: ${e.message}`))
      .finally(sambung);

    return () => {
      berhenti = true;
      clearTimeout(timerSambung);
      clearInterval(pengawas);
      ws?.close();
    };
  }, [muatRest, muatTerblokir, toast]);

  // Aksi admin. Backend menyiarkan hasilnya lewat WS; jawaban REST juga
  // di-upsert supaya tampilan tetap benar meski WS sedang terputus.
  const jalankan = useCallback(
    async (label: string, fn: () => Promise<unknown>) => {
      try {
        const hasil = await fn();
        if (hasil && typeof hasil === "object" && "jenis" in hasil && (hasil as Insiden).jenis === "insiden") {
          dispatch({ t: "insiden", data: [hasil as Insiden] });
        }
        toast("sukses", label);
        void muatTerblokir();
        return true;
      } catch (e) {
        toast("galat", `${label} gagal: ${(e as Error).message}`);
        return false;
      }
    },
    [muatTerblokir, toast],
  );

  const aksi = {
    setujui: (id: number) => jalankan(`Insiden #${id} disetujui`, () => api.setujui(id)),
    tolak: (id: number) => jalankan(`Insiden #${id} ditolak`, () => api.tolak(id)),
    cabut: (ip: string) => jalankan(`Blokir ${ip} dicabut`, () => api.cabutBlokir(ip)),
    blokir: (ip: string, durasi: number) =>
      jalankan(`${ip} diblokir ${durasi} menit`, () => api.blokirManual(ip, durasi)),
  };

  return { keadaan, toasts, aksi };
}
