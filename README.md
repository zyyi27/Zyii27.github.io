# Penilaian Ajang Kreatifitas Anak Sholih Sholihah (Versi Online)

Sistem penilaian lomba dengan server sendiri. Semua perangkat memakai data yang sama dan
saling tersinkron otomatis: asisten juri mengisi nilai, admin langsung melihatnya di Rekap.
Tidak ada lagi Ekspor dan Impor.

Server ini hanya memakai Node.js (versi 18 ke atas) tanpa pustaka tambahan.

## Cara kerja singkat
- Satu server menyimpan semua data di `DATA_DIR/db.json` dan membuat cadangan otomatis tiap jam.
- Halaman web dan API dilayani oleh server yang sama, jadi cukup satu alamat.
- Masuk memakai PIN. **Aturan dijaga di server**, bukan hanya di tampilan:
  - Asisten hanya bisa menulis dan melihat nilai **lomba miliknya**.
  - Nilai yang sudah dikirim atau hasil yang sudah disahkan **terkunci**. Mengubahnya lewat konsol browser pun ditolak server.
  - Koreksi hanya bisa dilakukan setelah **admin menyetujui** permintaan.
  - PIN asisten tidak pernah dikirim ke perangkat asisten. Percobaan PIN berulang dibatasi.

## 1. Coba di laptop (tanpa internet, cocok untuk cadangan di lokasi acara)
```
ADMIN_PIN=pin-rahasia node server.js
```
Buka `http://localhost:3000`. HP dan laptop lain di Wi-Fi yang sama membuka `http://ALAMAT-IP-LAPTOP:3000`
(cek alamat IP laptop, misalnya 192.168.1.10). Tidak perlu internet.
Di Windows (PowerShell): `$env:ADMIN_PIN="pin-rahasia"; node server.js`

## 2. Pasang online
Pastikan data disimpan di **disk permanen**. Banyak layanan gratis memakai disk sementara yang
terhapus saat server dimulai ulang. Itu berbahaya untuk data nilai.

### A. VPS atau server sendiri (disarankan)
1. Pasang Node.js 20, salin folder ini ke server, misalnya `/opt/penilaian`.
2. Buat layanan systemd `/etc/systemd/system/penilaian.service`:
```
[Unit]
Description=Penilaian Ajang
After=network.target
[Service]
WorkingDirectory=/opt/penilaian
Environment=PORT=3000 DATA_DIR=/var/lib/penilaian TRUST_PROXY=1 ADMIN_PIN=pin-rahasia
ExecStart=/usr/bin/node server.js
Restart=always
User=www-data
[Install]
WantedBy=multi-user.target
```
   Buat folder data: `sudo mkdir -p /var/lib/penilaian && sudo chown www-data /var/lib/penilaian`,
   lalu `sudo systemctl enable --now penilaian`.
3. Pasang Nginx sebagai pintu HTTPS (sertifikat gratis dengan certbot):
```
server {
  server_name penilaian.contoh.id;
  location / {
    proxy_pass http://127.0.0.1:3000;
    proxy_set_header X-Forwarded-For $remote_addr;
    proxy_http_version 1.1;
    proxy_read_timeout 60s;
    proxy_buffering off;
  }
}
```

### B. Railway, Render, Fly.io, atau sejenisnya
1. Unggah folder ini ke repository, hubungkan ke layanan, perintah mulai: `node server.js`.
2. Tambahkan **volume/disk permanen** (misalnya dipasang di `/data`) dan atur `DATA_DIR=/data`.
3. Atur variabel `ADMIN_PIN` dan `TRUST_PROXY=1`. Jalankan **hanya satu instance** server.
4. Tersedia juga `Dockerfile` jika layanannya mendukung Docker.

### C. Hosting cPanel yang punya "Setup Node.js App"
Unggah folder, buat aplikasi Node dengan berkas awal `server.js`, atur variabel lingkungan seperti di atas.
Tidak semua hosting biasa menyediakan Node.js. Jika tidak ada, gunakan VPS atau layanan B.

## 3. Langkah pertama setelah online
1. Buka alamatnya, pilih **Admin**, masuk dengan `ADMIN_PIN` (atau 1234 bila tidak diatur).
2. **Ganti PIN admin** lewat peringatan di Beranda.
3. Isi judul, logo, penandatangan (Pengaturan), kriteria, juri tiap lomba, asisten, dan peserta.
4. Asisten juri cukup membuka alamat yang sama dan masuk dengan PIN-nya. Tidak ada impor.
5. Coba satu putaran penuh dengan data contoh, lalu **Hapus semua data** di Beranda sebelum acara.

## 4. Cadangan dan pemulihan
- Otomatis: `DATA_DIR/cadangan-TANGGAL-JAM.json` tiap jam (72 terakhir disimpan).
- Manual: Data > **Unduh cadangan** (admin). Lakukan sebelum dan sesudah acara.
- Pulihkan: Data > **Pulihkan dari cadangan**, atau salin berkas cadangan menjadi `db.json` lalu mulai ulang server.

## 5. Batas dan catatan
- Satu proses dengan penyimpanan berkas. Cocok untuk ratusan peserta dan puluhan perangkat. Jangan menjalankan lebih dari satu instance.
- Gunakan **HTTPS** bila diakses lewat internet. PIN adalah pengunci, pilih PIN yang tidak mudah ditebak.
- Sesi login berlaku 12 jam dan bertahan saat server dimulai ulang.
- Jika koneksi terputus, aplikasi mencoba menyambung lagi otomatis. Nilai yang sudah diketik disimpan di perangkat dan dikirim ulang setelah tersambung. Perubahan yang ditolak server dikembalikan seperti di server.
- Pembuatan PDF dan pengiriman (Bagikan, Email, WhatsApp) jalan di browser. "Kirim otomatis" lewat webhook bisa dipakai di versi ini (lihat README versi hosting biasa).

## 6. Uji otomatis
`npm test` menjalankan 53 pemeriksaan (login, hak akses, penguncian, long-poll, cadangan, keamanan).
