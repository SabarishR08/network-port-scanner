# Network Port Scanner Web UI

A lightweight but advanced TCP port scanner with a browser-based UI built using Python and Flask.

## Features

- **Modern HTML dashboard** - responsive web interface with live status cards and progress tracking
- **Advanced scan controls** - target, port range, timeout, worker count, and quick scan profiles
- **Multi-threaded scanning** - up to 1000 concurrent workers for faster sweeps
- **Service identification** - labels common services (SSH, HTTP, SMB, RDP, MySQL, PostgreSQL, Redis, and more)
- **Live results stream** - open ports and diagnostics update in near real time
- **Stop on demand** - cancel scans gracefully
- **Export reports** - download a text report for each scan job
- **Cross-platform** - runs on Windows, macOS, and Linux

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
6. Click **Stop** to interrupt, or **Export** to download results.

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
└── README.md
```

## Disclaimer

Use this tool only on hosts and networks you own or have explicit permission to scan. Unauthorized port scanning may be illegal in your jurisdiction.

## License

This project is released under the [MIT License](https://opensource.org/licenses/MIT).
