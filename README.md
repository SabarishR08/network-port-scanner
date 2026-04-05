# PowerScan: Advanced Web-Based Network Recon Platform

PowerScan is an AI-assisted network reconnaissance tool that combines port scanning with concise risk analysis and controlled scanning modes.

![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-Web%20API-000000?logo=flask&logoColor=white)
![SQLite](https://img.shields.io/badge/Storage-SQLite-003B57?logo=sqlite&logoColor=white)
![AI](https://img.shields.io/badge/AI-Gemini%20%2B%20Groq-1f6feb)
![Export](https://img.shields.io/badge/Export-TXT%20%7C%20JSON%20%7C%20PDF-0A7E8C)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20macOS%20%7C%20Linux-4C8EDA)
![License](https://img.shields.io/badge/License-MIT-green)
[![Demo Video](https://img.shields.io/badge/Demo-Video-red?logo=google-drive&logoColor=white)](https://drive.google.com/file/d/1ma06I1Avt3lqvKm910m9ZBkdw4irzpkU/view?usp=sharing)

PowerScan is a modular network reconnaissance tool built with Python and Flask.

It extends a traditional TCP port scanner with service detection, AI-based risk classification, scan history comparison, and exportable reports.

## Why PowerScan

Most port scanners return raw network data. PowerScan focuses on interpreting that data by attaching short, consistent risk explanations and enforcing safer scanning defaults.

## Demo

View the demo video:
https://drive.google.com/file/d/1ma06I1Avt3lqvKm910m9ZBkdw4irzpkU/view?usp=sharing

## AI Source Badge Demo

PowerScan now shows which provider produced each risk result in the UI:

![Gemini](https://img.shields.io/badge/AI_Source-Gemini-00A3FF)
![Groq](https://img.shields.io/badge/AI_Source-Groq-54b948)
![Fallback](https://img.shields.io/badge/AI_Source-Fallback-orange)

If Gemini is unavailable or rate-limited, PowerScan automatically falls back to Groq. If both fail, the result is marked as `Fallback` and still returns a deterministic risk line.

## Features

- Modular backend architecture:
	- `config.py` for environment and runtime settings
	- `scanner.py` for scanning/profiles/banner logic
	- `analyzer.py` for Gemini + Groq AI analysis
	- `utils.py` for helper logic (classification, recommendations, parsing)
	- `main.py` for API endpoints + orchestration
- Multi-threaded TCP scanning with configurable timeout and workers
- Smart service detection and banner probing:
	- HTTP request probe (`GET / HTTP/1.1`)
	- SSH handshake/banner detection
	- Service/version normalization
- AI risk analyzer with strict one-line output parsing:
	- `Risk: <Low/Medium/High> | Reason: <...>`
- Batched AI analysis (single request for all open ports) for lower latency/cost
- AI provider fallback chain:
	- Gemini first
	- Groq fallback
	- Deterministic fallback if both providers fail
- AI source attribution per port (`gemini`, `groq`, `fallback`) shown in UI
- Scan profiles:
	- `quick_scan` (top 100 ports)
	- `full_scan` (1-65535)
	- `stealth_scan` (lower threads, higher timeout)
	- `web_scan` (80, 443, 8080)
	- `custom` range
- SAFE_MODE / ADVANCED_MODE target controls:
	- SAFE_MODE allows only `127.0.0.1`, `scanme.nmap.org`, and private ranges
	- ADVANCED_MODE allows all targets
- Target classification:
	- `localhost`, `private`, `public`
	- Warning flag for public scans
- Result enrichment per open port:
	- `port`, `service`, `banner`, `risk`, `reason`, `ai_source`
- Recommendation engine based on exposed services
- Persistent scan history in SQLite
- History comparison:
	- new ports detected
	- ports closed
- Report export:
	- `TXT`
	- `JSON`
	- `PDF`
- Frontend dashboard:
	- Progress + status polling
	- Risk and reason columns
	- AI source badge column
	- Comparison and recommendations panels

## Requirements

- Python 3.10+
- pip

## Installation

```bash
git clone https://github.com/SabarishR08/network-port-scanner.git
cd network-port-scanner
pip install -r requirements.txt
```

## Environment Setup

Create a `.env` file at project root:

```env
GEMINI_API_KEY=your_gemini_key
GROQ_API_KEY=your_groq_key
GEMINI_MODEL=gemini-2.0-flash
GROQ_MODEL=llama-3.1-8b-instant

# Optional runtime settings
HOST=0.0.0.0
PORT=5000
SCAN_MODE=SAFE_MODE
MAX_ACTIVE_JOBS=3
MAX_STORED_JOBS=50
```

## Run

```bash
python portscanergui.py
```

Open:

- `http://127.0.0.1:5000`

## API Endpoints

- `POST /api/scan/start` - start a new scan
- `POST /api/scan/<job_id>/stop` - stop/close active job (compat endpoint)
- `GET /api/scan/<job_id>/status` - job status and results
- `GET /api/scan/<job_id>/export?format=txt|json|pdf` - export report
- `GET /api/history?limit=20` - list history
- `GET /api/history/<job_id>` - load one history item

## Sample Scan Start Payload

```json
{
	"target": "scanme.nmap.org",
	"profile": "web_scan",
	"mode": "SAFE_MODE",
	"banner_grab": true,
	"timeout": 0.6,
	"max_workers": 120
}
```

## Project Structure

```text
network-port-scanner/
├── portscanergui.py
├── main.py
├── scanner.py
├── analyzer.py
├── utils.py
├── config.py
├── templates/
│   └── index.html
├── static/
│   ├── app.js
│   └── styles.css
├── requirements.txt
├── .env                  # local only (ignored)
├── scan_history.db       # runtime DB
└── README.md
```

## Security Notes

- Scan only systems you own or have permission to test.
- Store API keys in `.env`; do not commit them.
- Public targets trigger a warning in the UI/API.
- SAFE_MODE is recommended for controlled environments.

## Disclaimer

Unauthorized scanning may be illegal in your jurisdiction. Use responsibly and only with permission.

## License

This project is released under the [MIT License](https://opensource.org/licenses/MIT).
