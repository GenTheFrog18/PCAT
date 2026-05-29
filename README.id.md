# PCAT - PCAP Assistant for Triage

PCAT adalah tool command-line offline untuk analisis awal packet capture. PCAT menerima capture yang bisa dibaca TShark/Wireshark, termasuk `.pcap`, `.pcapng`, `.cap`, `.pcap.gz`, dan capture valid dengan ekstensi tidak umum. Tool ini dibuat untuk triage jaringan dan workflow CTF, terutama saat pertanyaan awalnya adalah: isi capture ini apa, bagian mana yang penting, dan harus mulai cek dari mana?

## Kebutuhan

- Python 3.10+
- `tshark` dari Wireshark

Opsional:

- `scikit-learn` untuk ML anomaly scoring
- `pytest` untuk menjalankan test

Install dari root repository:

```bash
python3 -m pip install -e .
```

Jalankan tanpa install:

```bash
PYTHONPATH=src python3 -m pcat --help
```

## Command Umum

```bash
pcat doctor
pcat summary -i capture.pcap
pcat analyze -i capture.pcap --ctf --no-ml
pcat evidence -i capture.pcap --top 25
pcat timeline -i capture.pcap --top 50
pcat hunt -i capture.pcap --limit 50
pcat strings -i capture.pcap --grep flag --ignore-case
pcat strings -i capture.pcap --source packet --grep flag
pcat search -i capture.pcap password --ignore-case
pcat search -i capture.pcap firmware --scope protocols
pcat artifacts -i capture.pcap --top 50
pcat artifacts -i capture.pcap --suspicious --top 20
pcat extract -i capture.pcap --tftp -o case-output
pcat extract -i capture.pcap --http --limit 10
```

Report dan artifact dibuat di `<nama-file-pcap>-pcat/<stem-pcap>/` kecuali user memberi `-o/--out`. Contoh: `capture.pcapng` akan memakai `capture.pcapng-pcat/capture/`. Folder output sudah di-ignore oleh git.

Setiap command mendukung `--json` untuk automation dan handoff ke tim.

## Kemampuan V2

- Summary capture dengan protocol, host, port, DNS, HTTP, TCP stream, dan UDP conversation.
- Input mengikuti kemampuan TShark, dengan pesan yang lebih jelas untuk archive, placeholder HTML/download gagal, file gzip, dan capture invalid.
- Metadata capture dengan SHA256, data `capinfos` jika tersedia, dan protocol hierarchy.
- Structured evidence dengan stable ID, confidence, preview, anchor frame/stream, dan handoff filter.
- Analyst briefing dan evidence stories untuk merangkum hal paling penting, batasan analisis, dan command berikutnya.
- Parser lebih aman untuk capture HTTP/multipart besar.
- Ekstraksi string dari payload TCP/UDP, termasuk Raw IPv4 TCP payload.
- Mode hunt untuk CTF: flag, flag dengan spasi, credential, clue string, fragment base64 pendek, rekonstruksi berdasarkan timestamp, banner payload ICMP, dan SYN packet yang membawa payload.
- Triage transfer HTTP memakai metadata request/response, content type, content length, dan indikasi upload/download besar.
- Bukti SMTP, MQTT, dan TFTP ditampilkan jika field tersedia dari TShark, termasuk evidence credential SMTP AUTH yang sudah di-decode dan grouping transfer TFTP. Export object TFTP tersedia lewat `pcat extract --tftp`.
- Ekstraksi DNS lebih luas untuk answer umum seperti A, AAAA, CNAME, PTR, NS, MX, dan TXT jika field tersedia dari TShark.
- Timeline memakai timestamp evidence jika tersedia, mengurutkan fallback evidence secara kronologis, dan menampilkan `unknown` daripada membuat waktu palsu `0.000000`.
- Deteksi artifact berbasis magic-byte dengan label certainty: `confirmed`, `candidate`, atau `rejected`, plus field trust untuk magic header, struktur, kelengkapan file, truncation, source scope, dan alasan skip. Executable PE/MZ ikut dideteksi dan diranking.
- Artifact manager terkonsolidasi dan membuat `artifacts/manifest.json`; rejected artifact digabung per tipe/alasan di stdout default, sementara offset detail tetap ada di JSON atau verbose output. `files`, `suspicious`, dan `tftp` tetap ada sebagai alias kompatibilitas tersembunyi dengan warning deprecation.
- Ekstraksi lebih aman: `--limit` membatasi file yang benar-benar ditulis, artifact invalid/incomplete tidak dipilih untuk extraction, raw carving harus opt-in, wrapper input `.pcap.gz` tidak dianggap artifact embedded, alasan skip dihitung, dan export HTTP/TFTP object dilaporkan terpisah dari artifact carving.
- `search` bisa mencari strings, hasil decode, protocol records, evidence, findings, dan artifacts dengan `--scope`; scope yang berbasis string mendukung `--source raw`, `--source packet`, atau `--source all`.
- Report JSON memakai `report.json`, `stories.json`, dan `evidence.json`; export CSV mencakup flows, hosts, DNS, HTTP, TFTP, artifacts, dan findings.
- Command rekomendasi sudah aman untuk path yang mengandung spasi.

## Batasan Saat Ini

- Artifact `candidate` adalah lead, bukan file yang sudah pasti valid. Periksa `complete_file_valid`, `truncated`, dan `source_scope` sebelum mempercayai hasil carving.
- Full TCP stream reassembly, export payload MQTT, decoding USB HID, dan decoder CTF yang lebih dalam masih rencana.
- PCAT sebaiknya dipakai sebagai tool briefing dan handoff bersama Wireshark/TShark dan tool spesialis lain.

## Dokumentasi

- Source GitHub Pages: [docs/index.html](docs/index.html). Publish dari branch `main` folder `/docs`.
- [docs/reference/PCAT_ARCHITECTURE.md](docs/reference/PCAT_ARCHITECTURE.md): filosofi produk, arsitektur, keputusan desain, model kontribusi, dan scope implementasi/rencana.
- [docs/reference/PCAT_TECHNICAL_REFERENCE.md](docs/reference/PCAT_TECHNICAL_REFERENCE.md): referensi teknis lengkap untuk command, data model, output, finding, artifact, dan fitur rencana.
- [docs/reference/PCAT_MANUAL.md](docs/reference/PCAT_MANUAL.md): manual command lengkap.
