# 🛡️ Praktikum P06 · Risiko AI/LLM dan Prompt Injection
### Mata Kuliah: Keamanan Sistem Informasi (PMI 1522)

Repositori ini memuat berkas tugas dan laporan praktikum **Minggu 6: Risiko AI/LLM dan Prompt Injection** pada program studi Manajemen Informatika, Jurusan Ekonomi dan Bisnis, Politeknik Negeri Lampung. Seluruh simulasi, portal praktikum, studi kasus, dan evaluasi keamanan dirancang berjalan secara *offline-first* menggunakan data sintetis serta mendukung pengujian *live* menggunakan LLM nyata (Google Gemini API).

---

## 👤 Identitas Praktikan

| Informasi | Keterangan |
| :--- | :--- |
| **Nama Lengkap** | **Septi Cahyaningtias** |
| **NPM** | **24781026** |
| **Kelas** | **MI-5A** |
| **Program Studi** | D3 Manajemen Informatika |
| **Institusi** | Politeknik Negeri Lampung (POLINELA) |
| **Repositori GitHub** | [septicahyaningtiaspolinela-ship-it/ksi-seca](https://github.com/septicahyaningtiaspolinela-ship-it/ksi-seca) |

---

## 🌐 Tautan Publik & Deployment

- **URL Publik Netlify**: 
- **URL Versi Rentan**: 
- **URL Versi Aman**: 
- **Repository GitHub**: https://github.com/septicahyaningtiaspolinela-ship-it/ksi-seca

---

## 📚 Informasi Akademik & Kontrak RPS

- **Mata Kuliah**: Keamanan Sistem Informasi (PMI 1522) — Semester 5
- **Dosen Pengampu RPS**:
  - M. Reza Redo Islami, S.Kom., M.T.I.
  - Akhmad Jayadi, S.Kom., M.Cs.
- **Standar & Acuan Kompetensi**:
  - **OWASP Top 10 for Large Language Model Applications** (LLM01: Prompt Injection, LLM06: Sensitive Information Disclosure, LLM08: Excessive Agency)
  - **NIST AI Risk Management Framework** (NIST AI RMF 1.0)
- **Capaian Pembelajaran (CPMK-1 / Sub-2)**:
  - Memahami dan menganalisis prinsip kontrol akses, arsitektur keamanan aplikasi AI, batasan hak istimewa (*least privilege*), ancaman *direct/indirect prompt injection*, mitigasi pengungkapan data sensitif, serta pengawasan manusia (*human oversight*).

---

## 🎯 Daftar Kasus Mandiri: Versi Rentan vs Versi Aman

Praktikum ini menyertakan empat pasang implementasi aplikasi simulasi interaktif (*Web Dummy LLM*) yang membandingkan kondisi rentan (*vulnerable*) terhadap mitigasi keamanan berlapis (*secure*):

### 1. Kasir Kantin Kampus (Voucher Manipulation)
- **Kategori Ancaman**: OWASP LLM01 — *Direct Prompt Injection*
- **Kondisi Rentan** ([`24781026-kantin-voucher-rentan.html`](24781026-kantin-voucher-rentan.html)): Prompt menyatukan instruksi sistem dan pesan pengguna dalam satu teks datar (*flat prompt*). Penyerang dapat menyuntikkan instruksi untuk memaksa asisten menerbitkan voucher diskon ilegal 100%.
- **Mitigasi Terproteksi** ([`24781026-kantin-voucher-aman.html`](24781026-kantin-voucher-aman.html)): Menerapkan *Instruction Hierarchy*, pembatasan hak (*Least Privilege* — tool voucher dipisahkan dari asisten), dan *Output Policy Validation*.

### 2. Peringkas Ulasan Marketplace (Indirect Injection)
- **Kategori Ancaman**: OWASP LLM01 — *Indirect Prompt Injection*
- **Kondisi Rentan** ([`24781026-ulasan-produk-rentan.html`](24781026-ulasan-produk-rentan.html)): Ulasan produk dari pihak ketiga yang belum terpercaya digabungkan langsung ke dalam prompt ringkasan tanpa isolasi atau delimiter.
- **Mitigasi Terproteksi** ([`24781026-ulasan-produk-aman.html`](24781026-ulasan-produk-aman.html)): Sanitasi input pihak ketiga, penggunaan *tag delimiter* terisolasi (`<untrusted_content>`), dan validasi bahwa ringkasan tidak memuat instruksi yang membelokkan output.

### 3. Rekap Pendaftaran UKM Kampus (Data Disclosure)
- **Kategori Ancaman**: OWASP LLM06 — *Sensitive Information Disclosure*
- **Kondisi Rentan** ([`24781026-rekap-ukm-rentan.html`](24781026-rekap-ukm-rentan.html)): Konteks prompt memuat seluruh data mentah calon anggota termasuk data pribadi (Nomor WhatsApp & Alamat Rumah).
- **Mitigasi Terproteksi** ([`24781026-rekap-ukm-aman.html`](24781026-rekap-ukm-aman.html)): Menerapkan *Context Minimization* (hanya mengirim data yang relevan ke LLM) dan melakukan *Data Redaction/Masking* terhadap PII (*Personally Identifiable Information*).

### 4. Agen Kalender Rapat Himpunan (Excessive Agency)
- **Kategori Ancaman**: OWASP LLM08 — *Excessive Agency*
- **Kondisi Rentan** ([`24781026-agen-rapat-rentan.html`](24781026-agen-rapat-rentan.html)): Asisten AI diberi akses otomatis untuk membatalkan rapat dan mengirim email notifikasi ke pihak luar tanpa persetujuan pengguna.
- **Mitigasi Terproteksi** ([`24781026-agen-rapat-aman.html`](24781026-agen-rapat-aman.html)): Menerapkan mekanisme *Human Oversight* / *Human-in-the-Loop* (HITL) dan *Tool Gating* dengan dialog konfirmasi eksplisit sebelum tindakan berdampak tinggi dijalankan.

---

## 📂 Struktur Direktori Proyek

```text
P06_Risiko_AI_LLM_dan_Prompt_Injection/
│
├── index.html                                 # Portal utama aplikasi praktikum P06
├── .gitignore                                 # File konfigurasi pengabaian file temporary/IDE
├── README.md                                  # Dokumentasi lengkap proyek
├── P06 · Risiko AI_LLM dan Prompt Injection... # Modul panduan praktikum resmi (PDF)
│
├── 24781026-kantin-voucher-rentan.html        # Kasus 1: Kasir Kantin (Versi Rentan)
├── 24781026-kantin-voucher-aman.html          # Kasus 1: Kasir Kantin (Versi Aman)
├── 24781026-ulasan-produk-rentan.html         # Kasus 2: Peringkas Ulasan (Versi Rentan)
├── 24781026-ulasan-produk-aman.html           # Kasus 2: Peringkas Ulasan (Versi Aman)
├── 24781026-rekap-ukm-rentan.html             # Kasus 3: Rekap UKM (Versi Rentan)
├── 24781026-rekap-ukm-aman.html               # Kasus 3: Rekap UKM (Versi Aman)
├── 24781026-agen-rapat-rentan.html            # Kasus 4: Agen Rapat (Versi Rentan)
├── 24781026-agen-rapat-aman.html              # Kasus 4: Agen Rapat (Versi Aman)
│
└── assets/
    ├── app.js                                 # Pengatur tab, navigasi, dan antarmuka utama
    ├── evidence.js                            # Generator bukti laporan A4 & manajemen backup JSON
    ├── lab-engine.js                          # Mesin simulator AI berbasis aturan offline
    ├── security-lab.js                        # Kontrak 4 demonstrasi lab terpandu & diff kontrol
    ├── task-bank.js                           # Bank soal 10 studi kasus evaluasi risiko AI
    ├── web-dummy.js                           # Runner verifikasi otomatis web dummy & skor
    ├── style.css                              # Desain antarmuka responsif dan tata letak cetak
    ├── logo-polinela.png                      # Logo institusi Politeknik Negeri Lampung
    └── logo-sdgs.jpg                          # Logo SDGs
```

---

## 🚀 Panduan Menjalankan Proyek

1. **Jalankan Portal Utama**:
   - Buka berkas `index.html` langsung di peramban web modern (Google Chrome, Firefox, Microsoft Edge, dll).
   - Proyek berjalan murni menggunakan HTML, CSS, dan JavaScript tanpa memerlukan *web server*, NodeJS, Python, atau database eksternal.

2. **Alur Praktikum**:
   - **Tab 01 Mulai**: Masukkan identitas praktikan dan setujui deklarasi etika pengujian keamanan.
   - **Tab 02 Teori**: Pelajari materi *Threat Modeling*, *Prompt Injection*, kebocoran PII, dan mitigasinya.
   - **Tab 03 Lab Terpandu**: Jalankan 4 siklus demonstrasi keamanan (Prediksi ➔ Pengujian Payload ➔ Pemilihan Kontrol ➔ Retest Mitigasi).
   - **Tab 04 Studi Kasus & Latihan**: Selesaikan 10 studi kasus penilaian dan uji halaman *Web Dummy*.
   - **Tab 05 Rekap**: Tinjau nilai akhir, simpan cadangan (*backup*) berkas JSON, dan cetak laporan resmi A4.

3. **Pengujian Mandiri Halaman Web Dummy**:
   - Buka masing-masing berkas HTML `24781026-*.html` langsung pada browser.
   - Gunakan tombol **Uji Cepat (Preset Payload)** untuk melihat perbedaan respon antara versi rentan dan versi terlindungi.
   - Tersedia opsi memasukkan *API Key Google Gemini* secara mandiri dan aman (kunci hanya disimpan di memori sesi peramban dan tidak pernah tercatat di repositori).

---

## 🔒 Kebijakan Keamanan & Etika Pengujian

- Seluruh data nama mahasiswa, katalog menu, ulasan marketplace, dan riwayat rapat yang digunakan dalam simulator bersifat **sintetis** (*dummy data*).
- Pengujian teknik *Prompt Injection* ini ditujukan khusus untuk tujuan akademis dan riset pertahanan sistem informasi sesuai etika *responsible disclosure*.
- Repositori ini **tidak memuat** API Key atau kredensial rahasia apapun.

---

*Hak Cipta © 2026 Septi Cahyaningtias (NPM: 24781026) · Manajemen Informatika Politeknik Negeri Lampung.*
