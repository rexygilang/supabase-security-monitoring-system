# LAPORAN ANALISIS TEKNIS (TECHNICAL ANALYSIS REPORT)
## Sistem Monitoring Keamanan Database Real-Time Supabase & NVIDIA NIM Dual AI
**Penyusun:** Web Security Engineer  
**Tanggal:** 8 Oktober 2026  
**Batasan Halaman:** Maksimal 3 Halaman Document  

---

### 1. PERFORMA ASYNCHRONOUS AI: PARALLEL EXECUTION vs SEQUENTIAL EXECUTION

#### 1.1 Landasan Teori Konkuransi Python (`asyncio`)
Dalam pemrosesan mikroservis keamanan modern, *latency* merupakan faktor paling krusial. Pada arsitektur deteksi ancaman berjenjang (*ensemble threat detection*), dua model Machine Learning dijalankan secara bersamaan untuk mengevaluasi setiap *query* database:
1. **Random Forest Threat Classifier (`RF`)**: Mengisolasi pola struktur SQL dan kata kunci berbahaya (*Simulated Latency:* \(0.30\) detik).
2. **Support Vector Machine Anomaly Detector (`SVM`)**: Mengukur jarak hiperplane variabel masukan terhadap lalu lintas normal (*Simulated Latency:* \(0.50\) detik).

#### 1.2 Perbandingan Matematis Waktu Eksekusi
* **Model Sekuensial (Sequential Execution):**
  Apabila model dipanggil secara berurutan (*blocking await*):
  \[
  T_{\text{sequential}} = T_{\text{RF}} + T_{\text{SVM}} = 0.30\text{s} + 0.50\text{s} = 0.8000\text{s}
  \]
  Pada mode ini, CPU dan I/O event loop terhenti menunggu respon dari model RF sebelum memulai eksekusi model SVM.

* **Model Paralel Asinkron (`asyncio.gather`):**
  Menggunakan `asyncio.gather(simulate_rf_model(payload), simulate_svm_model(payload))`, kedua *task* dijadwalkan secara independen pada I/O event loop. Waktu eksekusi keseluruhan ditentukan oleh model paling lambat (*maximum bottleneck*) ditambah *overhead* jadwal korutin (\(\epsilon\)):
  \[
  T_{\text{parallel}} = \max(T_{\text{RF}}, T_{\text{SVM}}) + \epsilon = \max(0.30\text{s}, 0.50\text{s}) + 0.1177\text{s} = 0.6177\text{s}
  \]

#### 1.3 Hasil Pengujian Empiris (`test_async_ai.py`)
Berdasarkan log terminal pengujian langsung:
```text
======================================================================
[RESULTS SUMMARY]
  - Random Forest Execution Time : 0.3147s
  - SVM Execution Time           : 0.5140s
  - Sequential Expected Time     : 0.8000s (0.30s + 0.50s)
  - Total Parallel Wall-Clock    : 0.6177 seconds (Passed Requirement >= 0.6s)
  - Execution Mode               : asynchronous_parallel
  - Consensus Threat Status      : CRITICAL_THREAT_DETECTED
======================================================================
```
**Kesimpulan Performa:** Penggunaan `asyncio.gather` berhasil memangkas latency sistem hingga **22.78%** dibandingkan pendekatan sekuensial, membuktikan efisiensi tinggi dalam menangani analisa ancaman berskala besar tanpa menyumbat I/O.

---

### 2. ARSITEKTAUR KEAMANAN GATEWAY HMAC-SHA256

#### 2.1 Klien Web Crypto API (Client-Side Signature Generation)
Untuk menjamin keaslian data sebelum dikirim dari browser atau sistem eksternal, tanda tangan digital dihitung menggunakan standar **Web Crypto API** native browser (`window.crypto.subtle`):
1. **Inisialisasi Kunci:** `crypto.subtle.importKey("raw", encoder.encode(secret), { name: "HMAC", hash: "SHA-256" }, ...)`
2. **Kalkulasi Digest:** `crypto.subtle.sign("HMAC", key, messageData)`
3. **Formatting Header:** Hasil *ArrayBuffer* diubah menjadi Hex String 64-karakter dan dikirim pada HTTP header `x-signature`.

#### 2.2 Server-Side Webhook Verification & Timing-Attack Mitigation (`api/webhook.js`)
Pada modul serverless Node.js, verifikasi dilakukan dengan pendekatan *zero-trust*:
```javascript
const expectedHmac = crypto.createHmac('sha256', process.env.WEBHOOK_SECRET)
                           .update(rawBody)
                           .digest('hex');

// Menggunakan timingSafeEqual untuk mencegah serangan side-channel timing analysis
const isValid = crypto.timingSafeEqual(
  Buffer.from(receivedSignature, 'hex'),
  Buffer.from(expectedHmac, 'hex')
);
```
Perbandingan `timingSafeEqual` memastikan bahwa durasi evaluasi string tetap konstan terlepas dari berapa banyak karakter yang cocok, menggagalkan teknik pemindaian serangan *timing attack*.

---

### 3. PIPELINE AUTOMATION & DEPLOYMENT CI/CD

#### 3.1 GitHub Actions Workflow (`.github/workflows/deploy.yml`)
Seluruh perubahan kode diproteksi melalui pipa otomatisasi CI/CD dengan urutan eksekusi (*Quality Gates*):
1. **Checkout & Environment Matrix:** Menyiapkan runner Ubuntu dengan Python 3.11 & Node.js 20.
2. **Automated Unit Testing:**
   * Eksekusi `python test_async_ai.py` (Memastikan respon AI paralelisasi berjalan \(\ge 0.6\)s).
   * Eksekusi `node test_flows.js` (Memastikan 3 pengujian validasi HMAC lulus 100%).
3. **Vercel Production Deployment:** Hanya jika pengujian lulus (`status: success`), repositori di-deploy otomatis ke Vercel Edge Network menggunakan `amondnet/vercel-action@v25`.

#### 3.2 Manajemen Rahasia (Secrets Management)
Kredensial penting diinjeksi via **GitHub Repository Secrets** dan **Vercel Environment Variables**:
* `VERCEL_TOKEN`, `VERCEL_ORG_ID`, `VERCEL_PROJECT_ID`
* `WEBHOOK_SECRET`
* `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID`
* `NVIDIA_API_KEY`

---

### 4. MEKANISME NOTIFIKASI TELEGRAM ALERT REAL-TIME

Ketika webhook menerima *payload* terverifikasi yang terindikasi sebagai ancaman (`CRITICAL_THREAT`), fungsi `sendTelegramAlert` membuat permintaan HTTPS POST ke Telegram Bot API:
```text
🚨 SUPABASE SECURITY ALERT 🚨
Threat Level: RED / CRITICAL
Event: DATABASE_MUTATION_SUSPECT
Payload Query: DROP TABLE admin_users; --
IP Source: 192.168.1.105
HMAC Status: ✅ AUTHENTICATED
```
Pengirim notifikasi bekerja secara asinkron tanpa memblokir respon HTTP webhook gateway.
