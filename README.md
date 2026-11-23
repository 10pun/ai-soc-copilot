# AI SOC Copilot

An API-first phishing and threat detection copilot for SOC analysts. It identifies credential-theft language, urgency cues, dangerous attachments, suspicious URLs, brand impersonation, IP-hosted links, and extracts URLs, IP addresses, and email indicators.

> Defensive tool: detections are explainable heuristics, not a substitute for malware sandboxing or a threat-intelligence platform.

## Run locally

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Open `http://localhost:8000/docs` for the interactive API.

## Docker

```bash
docker build -t ai-soc-copilot .
docker run --rm -p 8000:8000 ai-soc-copilot
```

## Example

```bash
curl -X POST http://localhost:8000/analyze \
  -H 'Content-Type: application/json' \
  -d '{"subject":"Urgent: verify password","sender":"security@microsoft-support.com","body":"Reset immediately at http://185.10.20.30/login"}'
```

## Test

```bash
pytest -q
```

## API

- `GET /health` — service health
- `POST /analyze` — phishing verdict, score, confidence, and evidence
- `POST /indicators/extract` — extract IP, URL, and email indicators
