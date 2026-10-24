# Hasil Eksperimen 2 — Metrik Evaluasi Model

Evaluasi dengan skema **hold-out per-sesi** (latih sesi 1–3, uji sesi 4) agar bebas
kebocoran data. Dataset uji (sesi 4): **61.383 flow** — normal 45.148, port_scanning
9.826, ddos_flood 6.409. Sumber angka: [`hasil_evaluasi.json`](hasil_evaluasi.json).
Analisis lengkap: [`../../docs/eksperimen2.md`](../../docs/eksperimen2.md).

## Ringkasan metrik

| Model | Accuracy | Precision (makro) | Recall (makro) | F1 (makro) |
|-------|----------|-------------------|----------------|------------|
| **Random Forest** (terbaik) | **99,77%** | 99,50% | 99,65% | **99,57%** |
| XGBoost | 99,71% | 99,40% | 99,57% | 99,48% |

Model yang dipasang di sistem live (dashboard + mitigasi) adalah **Random Forest**.

## Confusion Matrix — Random Forest
Baris = kelas sebenarnya, kolom = prediksi. Urutan kelas: `ddos_flood`, `normal`, `port_scanning`.

| aktual \ prediksi | ddos_flood | normal | port_scanning |
|-------------------|-----------|--------|---------------|
| **ddos_flood**    | 6355 | 54 | 0 |
| **normal**        | 89 | 45059 | 0 |
| **port_scanning** | 0 | 1 | 9825 |

Kesalahan hanya di batas **ddos_flood ↔ normal** (54 + 89 flow); port_scanning
hampir sempurna. Pola ini wajar: flood bervolume rendah bisa menyerupai trafik normal.
Visual: [`confusion_matrix.png`](confusion_matrix.png).

## Confusion Matrix — XGBoost

| aktual \ prediksi | ddos_flood | normal | port_scanning |
|-------------------|-----------|--------|---------------|
| **ddos_flood**    | 6341 | 68 | 0 |
| **normal**        | 107 | 45041 | 0 |
| **port_scanning** | 0 | 0 | 9826 |

## Feature Importance — Random Forest
Visual: [`feature_importance.png`](feature_importance.png).

| Fitur | Importance |
|-------|-----------|
| dst_port_count | 0,355 |
| duration | 0,177 |
| byte_count | 0,148 |
| packet_count | 0,126 |
| unique_src_ip_per_dst | 0,066 |
| inter_arrival_time | 0,060 |
| syn_flag_count | 0,022 |
| flow_rate | 0,022 |
| avg_packet_size | 0,021 |
| protocol | 0,004 |

Kepentingan tersebar di banyak fitur (bukan satu fitur dominan), menandakan model
belajar pola yang masuk akal — berbeda dengan Eksperimen 1 yang bergantung pada
fitur *zero-variance*. Lihat [`../exp1/metrik.md`](../exp1/metrik.md).
