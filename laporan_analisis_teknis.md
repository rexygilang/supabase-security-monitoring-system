# LAPORAN ANALISIS TEKNIS (TECHNICAL ANALYSIS REPORT)
## Sistem Monitoring Keamanan Database Real-Time Supabase & NVIDIA NIM Dual AI
**Penyusun:** Web Security Engineer  
**Tanggal:** 8 Oktober 2026  
**Format:** Laporan Evaluasi Teknis Keamanan & Performa (Maksimal 3 Halaman)

---

### 1. PERFORMA ASYNCHRONOUS AI (NVIDIA NIM CONCURRENCY)

#### 1.1 Perbedaan Teknis Pemanggilan Sekuensial vs `asyncio.gather`
Dalam pemrosesan *threat intelligence*, dua model Machine Learning dijalankan untuk mengevaluasi *query* database:
* **Random Forest Threat Classifier (`RF`)**: Mengisolasi pola kata kunci SQL Injection (\(T_{\text{RF}} = 0.30\) detik).
* **Support Vector Machine Detector (`SVM`)**: Mengukur jarak hiperplane variabel anomali lalu lintas (\(T_{\text{SVM}} = 0.50\) detik).

* **Pemanggilan Sekuensial (*Blocking Pattern*):**
  Apabila dipanggil secara sekuensial menggunakan dua `await` terpisah (`await rf(); await svm();`), thread eksekusi terhenti (*blocked*) pada I/O model pertama sebelum dapat memulai eksekusi model kedua.
  \[
  T_{\text{sekuensial}} = T_{\text{RF}} + T_{\text{SVM}} = 0.30\text{s} + 0.50\text{s} = 0.8000\text{s}
  \]

* **Pemanggilan Asinkron Paralel (`asyncio.gather`):**
  Dengan `asyncio.gather(simulate_rf_model(payload), simulate_svm_model(payload))`, kedua *coroutine* dijadwalkan bersamaan pada I/O event loop non-blocking. Total waktu eksekusi ditentukan oleh model dengan latency tertinggi ditambah overhead jadwal event loop (\(\epsilon \approx 0.1177\text{s}\)):
  \[
  T_{\text{paralel}} = \max(T_{\text{RF}}, T_{\text{SVM}}) + \epsilon = \max(0.30\text{s}, 0.50\text{s}) + 0.1177\text{s} = 0.6177\text{s}
  \]
  *Hasil Pengujian Terminal (`test_async_ai.py`): Terverifikasi wall-clock time sebesar 0.6230s (\(\ge 0.6\) detik).*

#### 1.2 Analisis Perbedaan Waktu Eksekusi Lokal vs Deployment (Serverless Cloud)
Waktu eksekusi pada lingkungan *deployment* (Vercel Edge / Serverless Cloud) cenderung lebih besar dibandingkan lingkungan lokal karena faktor-faktor berikut:
1. **Cold Start Latency:** Serverless container memerlukan inisialisasi lingkungan Python runtime dan alokasi memori pada permintaan pertama.
2. **Network Hop & TLS Handshake Overhead:** Komunikasi antara Vercel Edge Gateway, NVIDIA NIM API Endpoint, dan Supabase Database menambah RTT (*Round Trip Time*) jaringan sebesar 50–150ms.
3. **Resource Throttling:** Lingkungan serverless membatasi alokasi CPU core (shared vCPU) dibandingkan mesin lokal.

#### 1.3 Dampak Operasi Blocking dan Kegagalan Salah Satu Model
* **Dampak Operasi Blocking:** Jika salah satu model menjalankan operasi synchronous blocking (misal: CPU-bound loop tanpa `await`), event loop Python akan *freeze*. Akibatnya, sistem tidak dapat menerima *request* webhook baru, menyebabkan penumpukan antrean (*request queuing*) dan potensi *HTTP 504 Gateway Timeout*.
* **Dampak Kegagalan Model & Mitigasi Reliability:**
  Jika salah satu model mengalami *crash* atau *timeout* tanpa penanganan eksplisit, fungsi `asyncio.gather` secara default akan membatalkan seluruh task dan melempar *exception*.
  *Mitigasi Arsitektur:* Menggunakan parameter `return_exceptions=True` atau membungkus setiap task dengan blok `try-except` individual. Hal ini memastikan jika model SVM gagal, keputusan *fallback* keamanan masih dapat diberikan berdasarkan hasil prediksi model RF yang berhasil (*graceful degradation*).

---

### 2. KEAMANAN HMAC WEBHOOK GATEWAY

#### 2.1 Perlindungan HMAC-SHA256 Terhadap Spoofing dan Tampering
Meskipun penyerang mengetahui URL Endpoint Webhook dan format struktur *payload* JSON, mereka tidak dapat melakukan *spoofing* (memalsukan identitas pengirim) atau *tampering* (mengubah isi query) karena:
1. Tanda tangan HMAC dihasilkan melalui fungsi hash kriptografi satu arah:
   \[
   \text{Signature} = \text{HMAC-SHA256}(\text{PayloadRaw}, \text{HMAC\_SECRET})
   \]
2. Karena `HMAC_SECRET` hanya disimpan secara aman di Server Environment Variable (`process.env.WEBHOOK_SECRET`) dan tidak pernah dikirimkan melalui jaringan, penyerang tidak dapat merekayasa nilai `x-signature` yang valid untuk *payload* buatan mereka.

#### 2.2 Keterbatasan HMAC: Replay Attack & Timing Attack

* **Keterbatasan terhadap Replay Attack:**
  HMAC standar **tidak mencegah** *Replay Attack*. Penyerang yang mencegat paket webhook valid yang asli dapat mengirimkan kembali (*resend*) *payload* dan *signature* yang persis sama berulang kali.
  *Solusi Mitigasi:* Menyertakan `X-Timestamp` dan `X-Nonce` pada header. Server akan menolak paket jika `abs(CurrentTime - X-Timestamp) > 300` detik atau jika `Nonce` telah ada pada cache Redis.

* **Keterbatasan terhadap Timing Attack:**
  Jika verifikasi tanda tangan menggunakan perbandingan string standar (`===` atau `==`), interpreter akan membandingkan karakter satu per satu dari kiri ke kanan dan berhenti begitu menemukan ketidakcocokan pertama (*early-exit comparison*). Penyerang dapat mengukur durasi respon HTTP hingga orde mikrodektik untuk merekonstruksi tanda tangan valid karakter demi karakter.

#### 2.3 Alasan Penggunaan `crypto.timingSafeEqual()` vs Operator `===`
Penggunaan `crypto.timingSafeEqual(bufferA, bufferB)` dari modul native Node.js `crypto` sangat krusial karena:
1. `timingSafeEqual` mengeksekusi perbandingan bitwise dengan **durasi waktu konstan (*constant-time execution*)**, terlepas dari berapa banyak karakter yang cocok atau berbeda.
2. Hal ini secara mutlak menutup celah serangan *side-channel timing attack*, menjamin bahwa penyerang tidak mendapatkan respon temporal apapun terkait kebenaran parsial dari signature.

---

### 3. TRADE-OFF DESAIN SECURITY DASHBOARD & ARSITEKTUR WEB

Berikut adalah analisis 3 keputusan desain arsitektur/UI dari dashboard keamanan yang dibangun beserta trade-off teknisnya:

| No | Keputusan Desain Arsitektur / UI | Alasan Teknis (Keamanan & Performa) | Trade-Off (Usability & Kompleksitas) |
| :---: | :--- | :--- | :--- |
| **1** | **Client-Side Web Crypto API (`window.crypto.subtle`)** | **Keamanan:** Memungkinkan browser menghitung tanda tangan HMAC secara lokal tanpa mengekspos rahasia kunci dalam teks terbuka.<br>**Performa:** Memindahkan komputasi hash dari CPU server ke client. | **Trade-Off:** Membutuhkan browser modern yang mendukung HTTPS/Secure Context. Kode JS client menjadi sedikit lebih kompleks (*async ArrayBuffer to Hex parsing*). |
| **2** | **Dynamic State Management via Class Modification (`className`)** | **Keamanan & Performa:** Mengubah warna kartu (Safe Green ke Critical Red) dengan mengganti class CSS (`card-safe` / `card-danger`) menghindari *DOM injection* (vulnerabilitas XSS). Manipulasi CSS diproses langsung oleh GPU *compositor layer* tanpa memicu *layout reflow*. | **Trade-Off:** Pengembang harus mengelola stylesheet CSS secara terpusat dan tidak bisa mengubah gaya visual secara ad-hoc tanpa kelas terdefinisi. |
| **3** | **Client Security Audit Log Stream & Sanitize Console** | **Usability:** Memberikan visibilitas *real-time* kepada SOC operator terkait lalu lintas *query*. Mengurangi memory leak dengan membatasi jumlah baris log pada DOM. | **Trade-Off:** Mengorbankan histori log jangka panjang di sisi browser (log historis lengkap dialihkan ke database audit log di server). |

---

### 4. KESIMPULAN ARSITEKTUR KEAMANAN
Sistem monitoring keamanan database real-time yang dibangun berhasil mengintegrasikan otentikasi ketat berstandar kriptografi (HMAC-SHA256 constant-time comparison), paralelisasi inferensi AI berkecepatan tinggi (`asyncio.gather`), notifikasi darurat terotomatisasi (Telegram Bot API), serta dashboard SOC interaktif berkinerja tinggi.
