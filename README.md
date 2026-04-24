# PhishGuard — AI-Powered Phishing Email Analyzer

A cybersecurity tool that uses Claude (Anthropic) to analyze email headers and bodies for phishing indicators in real time.

## Features

- **AI Analysis** — Claude analyzes SPF/DKIM/DMARC failures, domain spoofing, urgency tactics, and suspicious URLs
- **Streaming results** — analysis appears word by word, no waiting for the full response
- **URL scanning** — extracts and flags suspicious links (IP-based URLs, typosquatted domains, shorteners)
- **Attachment scanning** — upload `.txt` or `.html` attachments for additional analysis
- **`.eml` file upload** — auto-parses exported email files, no manual copy-pasting needed
- **Scan history** — last 15 results stored locally in the browser
- **Per-client instructions** — step-by-step guide to copy headers from Gmail, Outlook, Apple Mail, Yahoo, and Thunderbird

## Security Measures

- Rate limited: 8 requests/minute, 60/day per IP
- 2 MB upload size cap
- Input length limits (20 KB header, 50 KB body)
- Prompt injection mitigation via `<user_content>` tagging
- Security headers: CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy
- File content validation (not just extension checking)
- Debug mode off

## Setup

### 1. Clone the repository

```bash
git clone https://github.com/your-username/phishing-analyzer.git
cd phishing-analyzer
```

### 2. Create a virtual environment

```bash
python -m venv venv

# Windows
venv\Scripts\activate

# Mac / Linux
source venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Add your API key

Create a `.env` file in the project root:

```
ANTHROPIC_API_KEY=your_api_key_here
```

Get your key at [console.anthropic.com](https://console.anthropic.com).

### 5. Run the app

```bash
python app.py
```

Open [http://127.0.0.1:5000](http://127.0.0.1:5000) in your browser.

## How to Use

1. **Get the raw email header** — select your email client from the left panel for instructions
2. **Paste the header** into the Raw Email Header field
3. **Paste the body** (optional — headers alone are enough)
4. **Or upload a `.eml` file** — this auto-fills both fields
5. Click **Analyze Email** and watch results stream in

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Python, Flask |
| AI | Anthropic Claude (`claude-sonnet-4-6`) |
| Rate Limiting | Flask-Limiter |
| Frontend | HTML, CSS, Vanilla JS |
| Markdown rendering | marked.js (CDN) |
| Environment | python-dotenv |

## Project Structure

```
phishing-analyzer/
├── app.py                  # Flask backend, Claude integration
├── templates/
│   └── index.html          # Single-page frontend
├── requirements.txt        # Direct dependencies
├── .env                    # API key (not committed)
├── .gitignore
└── README.md
```

## Privacy Notice

Email content submitted for analysis is sent to Anthropic's API. Do not submit emails containing passwords, payment details, or confidential company information.

## License

MIT
