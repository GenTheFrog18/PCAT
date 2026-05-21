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
pcat search -i capture.pcap password --ignore-case
pcat files -i capture.pcap --top 50
pcat artifacts -i capture.pcap --top 50
pcat suspicious -i capture.pcap --top 20
pcat extract -i capture.pcap --limit 10
```

Report dan artifact dibuat di `<nama-file-pcap>-pcat/<stem-pcap>/` kecuali user memberi `-o/--out`. Contoh: `capture.pcapng` akan memakai `capture.pcapng-pcat/capture/`. Folder output sudah di-ignore oleh git.

Setiap command mendukung `--json` untuk automation dan handoff ke tim.

## Kemampuan V2

- Summary capture dengan protocol, host, port, DNS, HTTP, dan stream.
- Input mengikuti kemampuan TShark, dengan pesan yang lebih jelas untuk archive, placeholder HTML/download gagal, file gzip, dan capture invalid.
- Metadata capture dengan SHA256, data `capinfos` jika tersedia, dan protocol hierarchy.
- Structured evidence dengan stable ID, confidence, preview, anchor frame/stream, dan handoff filter.
- Analyst briefing dan evidence stories untuk merangkum hal paling penting, batasan analisis, dan command berikutnya.
- Parser lebih aman untuk capture HTTP/multipart besar.
- Ekstraksi string dari payload TCP/UDP, termasuk Raw IPv4 TCP payload.
- Mode hunt untuk CTF: flag, credential, clue string, fragment base64 pendek, rekonstruksi berdasarkan timestamp, dan SYN packet yang membawa payload.
- Triage transfer HTTP memakai metadata request/response, content type, content length, dan indikasi upload/download besar.
- Bukti SMTP dan MQTT ditampilkan jika field tersedia dari TShark.
- Ekstraksi DNS lebih luas untuk answer umum seperti A, AAAA, CNAME, PTR, NS, MX, dan TXT jika field tersedia dari TShark.
- Deteksi artifact berbasis magic-byte dengan label certainty: `confirmed`, `candidate`, atau `rejected`.
- Artifact manager membuat `artifacts/manifest.json`; ekstraksi default fokus ke packet payload, raw carving harus opt-in.
- Ekstraksi lebih aman: `--limit` membatasi file yang benar-benar ditulis, artifact invalid dilewati, dan raw carving dibatasi.
- Report JSON memakai `report.json`, `stories.json`, dan `evidence.json`; export CSV mencakup flows, hosts, DNS, HTTP, artifacts, dan findings.
- Command rekomendasi sudah aman untuk path yang mengandung spasi.

## Batasan Saat Ini

- Certainty artifact adalah label triage, bukan jaminan bahwa hasil carving lengkap atau bisa dibuka.
- Timeline, stream reassembly, export TFTP, export payload MQTT, decoding USB HID, dan decoder CTF yang lebih dalam masih rencana.
- PCAT sebaiknya dipakai sebagai tool briefing dan handoff bersama Wireshark/TShark dan tool spesialis lain.

## Dokumentasi

- [docs/reference/PCAT_ARCHITECTURE.md](docs/reference/PCAT_ARCHITECTURE.md): filosofi produk, arsitektur, keputusan desain, model kontribusi, dan scope implementasi/rencana.
- [docs/reference/PCAT_TECHNICAL_REFERENCE.md](docs/reference/PCAT_TECHNICAL_REFERENCE.md): referensi teknis lengkap untuk command, data model, output, finding, artifact, dan fitur rencana.
- [docs/reference/PCAT_MANUAL.md](docs/reference/PCAT_MANUAL.md): manual command lengkap.
