# Network Port Scanner Web UI

![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-Web%20API-000000?logo=flask&logoColor=white)
![SQLite](https://img.shields.io/badge/Storage-SQLite-003B57?logo=sqlite&logoColor=white)
![Export](https://img.shields.io/badge/Export-TXT%20%7C%20CSV%20%7C%20JSON-0A7E8C)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20macOS%20%7C%20Linux-4C8EDA)
![License](https://img.shields.io/badge/License-MIT-green)

TCP port scanner with a browser UI built using Python and Flask.

## Features

- Web interface for running scans from browser
- Scan settings: target, port range, timeout, worker count, and preset ranges
- Multi-threaded scanning (up to 1000 workers)
- Optional banner grabbing for open ports
- Port-to-service labels for common ports
- Live progress and diagnostics while scan is running
- Stop running scan
- Scan history saved in SQLite (`scan_history.db`)
- Export scan results as `TXT`, `CSV`, or `JSON`
- Works on Windows, macOS, and Linux

## Requirements

- Python 3.10 or newer
- Flask

## Installation

```bash
git clone https://github.com/SabarishR08/network-port-scanner.git
cd network-port-scanner
pip install -r requirements.txt
```

## Usage

```bash
python portscanergui.py
```

Then open:

`http://127.0.0.1:5000`

1. Enter the **Target** host or IP.
2. Choose a **Scan Profile** or set a custom port range.
3. Tune **Timeout** and **Threads** if needed.
4. Click **Start Scan**.
5. Watch live progress and open ports.
6. Optional: enable **Banner Grab** to collect service banners/version hints.
7. Choose **Export Format** (`TXT`, `CSV`, `JSON`) and click **Export**.
8. Use **Scan History** to reload previous persisted scans after restart.

## API Endpoints

- `POST /api/scan/start` - start new scan
- `POST /api/scan/<job_id>/stop` - stop running scan
- `GET /api/scan/<job_id>/status` - current scan status
- `GET /api/scan/<job_id>/export?format=txt|csv|json` - export results
- `GET /api/history?limit=20` - list saved scan history
- `GET /api/history/<job_id>` - load one saved history item

## Scan Your Own IP (Windows)

1. Open Command Prompt and run:

```bash
ipconfig
```

2. From the active adapter (usually `Wi-Fi` or `Ethernet`), copy the `IPv4 Address`.
3. Use that IP as the **Target Host** in the scanner.

Notes:

- `127.0.0.1` scans localhost only.
- Your LAN IP (example: `10.x.x.x` or `192.168.x.x`) scans your machine on the network interface.

## Detected Services

The scanner auto-labels many common ports (sample below):

| Port | Service   |
|------|-----------|
| 20   | FTP-Data  |
| 21   | FTP       |
| 22   | SSH       |
| 23   | Telnet    |
| 25   | SMTP      |
| 53   | DNS       |
| 80   | HTTP      |
| 110  | POP3      |
| 143  | IMAP      |
| 445  | SMB       |
| 443  | HTTPS     |
| 3306 | MySQL     |
| 3389 | RDP       |
| 5432 | PostgreSQL|
| 6379 | Redis     |
| 5900 | VNC       |
| 8080 | HTTP-Alt  |
| 8443 | HTTPS-Alt |

Ports not in the list are reported as `Unknown`.

## Project Structure

```
network-port-scanner/
├── portscanergui.py   # Flask app + scan engine + API
├── templates/
│   └── index.html     # Main web UI
├── static/
│   ├── styles.css     # UI styles
│   └── app.js         # Frontend logic (API polling, rendering)
├── requirements.txt
├── scan_history.db    # Created at runtime (SQLite history)
└── README.md
```

## Security Notes

- The app limits concurrent active scan jobs to `3` to reduce abuse and accidental overload.
- Request payload size is capped server-side to prevent oversized request abuse.
- Export filenames are sanitized before download.
- Recommended for local/trusted environments; avoid exposing this scanner directly to the public internet.

## Disclaimer

Use this tool only on hosts and networks you own or have explicit permission to scan. Unauthorized port scanning may be illegal in your jurisdiction.

## License

This project is released under the [MIT License](https://opensource.org/licenses/MIT).
