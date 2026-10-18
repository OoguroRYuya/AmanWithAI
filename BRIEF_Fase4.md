# Phase 4 Brief — Dashboard Next.js (NDR / AmanWithAI)

> Self-contained. Phases 1–3 are done and on branch `dev` — read the backend
> code directly to confirm shapes; this brief already lists them. Build the
> frontend only. **Do NOT `git push`** — leave changes for the owner to commit.
> Dashboard language = **Bahasa Indonesia**. Review with the owner after Phase 4.

---

## 0. Context in one paragraph
This is a thesis NDR (Network Detection and Response) system. A trained
RandomForest classifies NetFlow into `normal` / `ddos_flood` / `port_scanning`.
The FastAPI backend (`backend/`) already ingests flows per 60s window, groups
attacks into **incidents**, applies auto-block gates, mitigates on VyOS via
Netmiko (SSH), and streams everything over a WebSocket. **Phase 4 is only the
dashboard** that reads the REST API for the initial page and the WebSocket for
live updates. No backend changes. Three attack classes, Indonesian UI.

The backend's eventual home is Windows PC B (out-of-band NDR server), but for
Fase 4 development you run **both the backend and the frontend on the same dev
machine** in **replay mode** (`SUMBER=replay`), so the dashboard ticks with real
data from `data/exp2/flows_sesi4.csv` against `localhost:8000` — no lab and no
PC B needed. Deploying the backend to PC B is a Fase 5 concern, not this phase.

---

## 1. Tech stack (confirmed)
- **Next.js (App Router) + TypeScript** in a new `frontend/` folder.
- **Recharts** for the stacked traffic chart.
- Plain CSS modules or Tailwind — your call; keep it clean and readable, not
  flashy. This is a thesis demo, so clarity > polish.
- Two env vars in `frontend/.env.local` (+ `.env.example`):
  - `NEXT_PUBLIC_API_URL=http://localhost:8000`
  - `NEXT_PUBLIC_WS_URL=ws://localhost:8000/ws`
- No auth, no SSR data fetching needed — it's a single-page client dashboard.
  Fetch REST once on mount, then live via WebSocket.

---

## 2. Data contract (VERIFIED against backend on `dev` — do not guess)

### REST (initial load)
- `GET /api/status` →
  ```json
  { "model_dimuat": true, "kelas": ["ddos_flood","normal","port_scanning"],
    "router": "192.168.42.198", "dry_run": true,
    "ambang_tinggi": 0.90, "ambang_sedang": 0.50, "min_flow_insiden": 20,
    "ambang_rasio_serangan": 0.80, "ambang_conf_blokir": 0.70,
    "allowlist": ["192.168.10.1","192.168.100.1","192.168.100.10","192.168.172.1","192.168.20.1","192.168.30.1"],
    "sumber_data": "replay", "estimasi_paket_paksa": false,
    "replay": {...|null}, "antrean": 0, "menunggu_persetujuan": 3,
    "total_deteksi": 72, "ip_terblokir": 241 }
  ```
- `GET /api/trafik` → list of traffic-window objects (same shape as the `trafik`
  WS message below, newest last). Use the latest ~60 for the chart on load.
- `GET /api/riwayat` → list of incident entries (same shape as the `insiden` WS
  message below). These are the incident table rows.
- `GET /api/persetujuan` → list of incidents in `menunggu_persetujuan` (approval
  queue) — same incident shape.
- `GET /api/terblokir` → `[ { "ip": "192.168.20.23", "kedaluwarsa": "2026-...isoformat", "sisa_detik": 873 }, ... ]`
- `GET /api/ringkasan` → aggregate counts (optional, for a summary card).

### WebSocket `/ws` (live)
On connect the server sends ONE `snapshot`, then streams the rest. **Message
types (the `tipe` field):**

```json
{ "tipe": "snapshot", "status": {<status obj above>},
  "insiden": [<up to 50 incident objs>], "terblokir": [<terblokir objs>],
  "trafik": [<up to 60 trafik objs>] }

{ "tipe": "trafik", "window": "2026-10-16T09:24:00",
  "per_kelas": {"normal": 4, "ddos_flood": 0, "port_scanning": 0},
  "byte_total": 352, "jumlah_backscatter": 4, "jumlah_insiden": 0,
  "jumlah_diabaikan": 0, "sumber_data": "replay",
  "t_window_end": "...", "t_diterima": "...", "t_klasifikasi": "..." }

{ "tipe": "insiden", "id": 42, "jenis": "insiden",
  "window": "2026-10-16T09:26:00", "kelas": "port_scanning",
  "kunci": "192.168.20.23", "jumlah_flow": 123,
  "sumber": ["192.168.20.23"], "tujuan": ["192.168.30.10"],
  "confidence": 0.78, "packet_total": 248, "byte_total": 10896,
  "dst_port_maks": 120, "jumlah_sumber": 1,
  "status": "blokir_otomatis" | "menunggu_persetujuan" | "ditolak" | "disetujui" | "dicatat",
  "alasan": "1 dari 1 sumber lolos gerbang",
  "ip_blokir": ["192.168.20.23"], "ip_kandidat": [],
  "evaluasi_sumber": [ {"ip":"...","rasio_serangan":1.0,"conf_rata":0.78,"lolos":true,"alasan":"..."} ],
  "saran": { "kelas":"port_scanning", "judul":"...", "tingkat":"Sedang",
             "narasi":"<multi-paragraph Indonesian text>", "saran_mitigasi":"...",
             "mitigasi_otomatis": true, "confidence": 0.78, ... },
  "dimitigasi": true, "t_window_end":"...", "t_diterima":"...",
  "t_klasifikasi":"...", "t_mitigasi":"...",
  "latensi_detik": {"deteksi": 0.07, "mitigasi": 0.27} }

{ "tipe": "mitigasi", "aksi": "blokir" | "cabut",
  "ip": ["192.168.20.23", "..."], "oleh": "otomatis" | "manual", "dry_run": true }

{ "tipe": "status", "model_dimuat": true, "dry_run": true, "ip_terblokir": 241 }

{ "tipe": "ping", "waktu": "..." }
```

**Crucial merge rule (owner-confirmed):** incidents arrive BOTH in the snapshot
AND as live `insiden` messages, and the same incident can be re-sent when its
status changes (e.g. `menunggu_persetujuan` → `disetujui`/`ditolak`). The
dashboard MUST **key incidents by `id`** and upsert (replace existing, don't
append a duplicate). Same for traffic windows — key by `window`. Do not append
blindly.

`mitigasi` messages are a feed/toast signal; the authoritative blocked-IP list
is the `terblokir` REST endpoint + the snapshot. When a `mitigasi` arrives,
refetch `GET /api/terblokir` (or apply optimistically and reconcile).

### Mitigation actions (POST)
- `POST /api/mitigasi/blokir` body `{ "ip": "1.2.3.4", "durasi_menit": 15 }`
- `POST /api/mitigasi/cabut` body `{ "ip": "1.2.3.4" }`
- `POST /api/mitigasi/setujui/{id}` (optional `?durasi_menit=`) — approve a
  queued incident → blocks its `ip_kandidat`.
- `POST /api/mitigasi/tolak/{id}` — reject a queued incident (no firewall change).

All of these also broadcast WS messages, so the live view updates itself after
the call succeeds.

---

## 3. Dashboard layout (what to build)

One page, Indonesian labels. Sections top to bottom:

1. **Baris status** (status row / header). Show: model dimuat ✓, mode
   `DRY RUN` vs `AKTIF` (prominent badge — dry_run=true means no real blocking),
   sumber data (replay/ingest), jumlah IP terblokir, jumlah menunggu persetujuan,
   koneksi WebSocket (tersambung / terputus). A small "ambang" readout
   (rasio ≥ 0.80, conf blokir ≥ 0.70) is nice for the thesis demo.

2. **Grafik trafik real-time** (stacked area/bar, Recharts). X = window time,
   Y = flow count, three stacked series `normal` / `ddos_flood` / `port_scanning`.
   Updates as each `trafik` message arrives. Keep the last ~60 windows.
   **Colors:** read the `dataviz` skill before picking them; use a categorical
   palette, and keep normal visually calm vs attack classes alarming. Don't use
   pure red/green only (color-blind safety).

3. **Tabel insiden** (incident table). Columns: waktu/window, kelas (badge),
   kunci (IP korban utk ddos / IP scanner utk scan), jumlah_flow, jumlah_sumber,
   confidence, status (badge: blokir_otomatis / menunggu_persetujuan / ditolak /
   disetujui / dicatat). Row click → panel/modal showing `saran.narasi`
   (the multi-paragraph Indonesian narration) + `evaluasi_sumber` table
   (ip, rasio_serangan, conf_rata, lolos) + latensi_detik. Newest on top,
   upsert by `id`.

4. **Antrean persetujuan** (approval queue) — incidents with
   `status == "menunggu_persetujuan"` (confidence in the 0.50–0.70 band). Each
   row has **Setujui** and **Tolak** buttons calling the endpoints above. After
   a click, the incident re-broadcasts with its new status and leaves the queue.

5. **IP terblokir** (blocked IPs) — list from `/api/terblokir` with a live
   **countdown** from `sisa_detik`, and a **Cabut** (unblock) button per IP, plus
   a manual **Blokir** input (IP + durasi) at the top. Tick the countdown with a
   local 1s timer; refetch on `mitigasi` messages.

---

## 4. WebSocket client behavior
- Connect to `NEXT_PUBLIC_WS_URL` on mount.
- On `snapshot`: seed status, incidents (by id), terblokir, trafik (by window).
- On `trafik` / `insiden` / `status`: upsert into state.
- On `mitigasi`: show a brief toast + refetch `/api/terblokir`.
- On `ping`: ignore (or update a "last seen" clock).
- **Auto-reconnect** with backoff if the socket closes; on reconnect, re-seed
  from the fresh `snapshot` (so no state drift). Show the connection state in the
  status row.

---

## 5. Run / verify (dev)
Backend in one terminal (replay so the dashboard has live data):
```
cd backend
SUMBER=replay DRY_RUN=True REPLAY_INTERVAL_DETIK=3 REPLAY_CSV=data/exp2/flows_sesi4.csv \
  uvicorn main:app --host 0.0.0.0 --port 8000
```
(On Windows PowerShell set the env vars with `$env:SUMBER="replay"` etc., or use
`backend/.env`.) Frontend in another:
```
cd frontend && npm install && npm run dev
```
Open the dashboard: the traffic chart should tick every few seconds, incidents
should fill the table, ~72 incidents and ~241 blocked IPs should appear over a
full replay, the approval queue should hold the mid-confidence incidents, and
Setujui/Tolak/Cabut should work against the live backend.

## Done when
The dashboard loads from REST, then updates live over the WebSocket without
polling; incidents upsert by `id` (no duplicates between snapshot and stream);
the approval and block/unblock actions hit the backend and reflect live. Then
stop and show the owner the diff. **Do NOT git push.**

## Hard rules
- No backend changes, no retraining, no thesis text.
- Do NOT `git push` — leave the working tree for the owner.
- Everything in Bahasa Indonesia (UI text), code/comments can stay as the repo's
  convention.
