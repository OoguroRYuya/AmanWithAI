# Hasil Eksperimen 1 — Baseline (Akurasi 100% sebagai Artefak)

Eksperimen 1 adalah **baseline**. Random Forest dan XGBoost sama-sama mencapai
**akurasi 100%** dengan confusion matrix tanpa kesalahan (precision, recall, F1 =
1,000 untuk semua kelas), split 70:30 *stratified* acak (`random_state=42`).

> **Angka 100% ini BUKAN tanda model bagus, melainkan artefak realisme data.**
> Trafik tiap kelas terlalu seragam (satu perintah tetap per kelas, satu host sumber),
> sehingga muncul fitur *zero-variance* dan sidik jari tool yang memisahkan kelas
> secara sempurna tanpa model perlu belajar pola nyata.

Temuan ini yang mendasari perbaikan di **Eksperimen 2** (randomisasi serangan,
multi-host via IP alias, trafik bercampur waktu, dan evaluasi hold-out per-sesi).
Hasilnya di [`../exp2/metrik.md`](../exp2/metrik.md).

Analisis lengkap mengapa 100% adalah artefak: [`../../docs/eksperimen1.md`](../../docs/eksperimen1.md).

| Model | Accuracy | Precision | Recall | F1 | Catatan |
|-------|----------|-----------|--------|----|---------|
| Random Forest | 100% | 1,000 | 1,000 | 1,000 | Artefak — lihat penjelasan di atas |
| XGBoost | 100% | 1,000 | 1,000 | 1,000 | Artefak — lihat penjelasan di atas |
