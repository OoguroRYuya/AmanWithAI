import type { Insiden, StatusSistem, Terblokir, Trafik } from "./tipe";

export const API_URL = (process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000").replace(/\/$/, "");
export const WS_URL = process.env.NEXT_PUBLIC_WS_URL ?? "ws://localhost:8000/ws";

async function minta<T>(path: string, init?: RequestInit): Promise<T> {
  const r = await fetch(`${API_URL}${path}`, {
    ...init,
    headers: { "Content-Type": "application/json", ...init?.headers },
  });
  if (!r.ok) {
    // FastAPI mengirim {"detail": "..."} untuk HTTPException
    let pesan = `${r.status} ${r.statusText}`;
    try {
      const isi = await r.json();
      if (isi?.detail) pesan = typeof isi.detail === "string" ? isi.detail : JSON.stringify(isi.detail);
    } catch {
      /* badan bukan JSON */
    }
    throw new Error(pesan);
  }
  return r.json() as Promise<T>;
}

// ------------------------------------------------------------------ baca

export const ambilStatus = () => minta<StatusSistem>("/api/status");

export const ambilTrafik = (limit = 60) =>
  minta<{ total: number; data: Trafik[] }>(`/api/trafik?limit=${limit}`).then((r) => r.data);

// /api/riwayat juga memuat entri non-insiden (deteksi, mitigasi_manual, ...)
export const ambilInsiden = (limit = 500) =>
  minta<{ total: number; data: Insiden[] }>(`/api/riwayat?jenis=insiden&limit=${limit}`).then((r) => r.data);

export const ambilPersetujuan = () =>
  minta<{ data: Insiden[] }>("/api/persetujuan").then((r) => r.data);

export const ambilTerblokir = () =>
  minta<{ data: Terblokir[] }>("/api/terblokir").then((r) => r.data);

// ------------------------------------------------------------------ aksi

export const blokirManual = (ip: string, durasi_menit: number) =>
  minta<{ status: string; ip: string }>("/api/mitigasi/blokir", {
    method: "POST",
    body: JSON.stringify({ ip, durasi_menit }),
  });

export const cabutBlokir = (ip: string) =>
  minta<{ status: string; ip: string }>("/api/mitigasi/cabut", {
    method: "POST",
    body: JSON.stringify({ ip }),
  });

export const setujui = (id: number) =>
  minta<Insiden>(`/api/mitigasi/setujui/${id}`, { method: "POST" });

export const tolak = (id: number) =>
  minta<Insiden>(`/api/mitigasi/tolak/${id}`, { method: "POST" });
