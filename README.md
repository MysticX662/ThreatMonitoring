# Threat Intelligence Hub

A serverless Threat Intelligence Hub that acts as both a **data scraper** and a **static API**.

## How It Works

Python scripts in `src/` fetch and process threat intelligence data from external sources, then write the results as static JSON files into `api/v1/`. The Next.js frontend in `web/` reads directly from these JSON files — no backend server required at runtime.

```
[External Sources] → src/ (scrapers) → api/v1/*.json → web/ (Next.js frontend)
```

## Project Structure

```
ThreatMonitoring/
├── src/               # Python scraper scripts
├── api/
│   └── v1/            # Static JSON data (output of scrapers)
├── web/               # Next.js frontend
├── requirements.txt   # Python dependencies
└── .env               # Environment variables (not committed)
```

## Setup

### Python (scrapers)

```bash
python -m venv venv
source venv/bin/activate       # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### Next.js (frontend)

```bash
cd web
npx create-next-app@latest .
npm run dev
```

### Environment Variables

Copy `.env.example` to `.env` and fill in your API keys:

```bash
cp .env.example .env
```

## Running the Scrapers

```bash
python src/<scraper_name>.py
```

Each scraper writes its output to `api/v1/<feed_name>.json`. Commit the JSON files to serve them as a static API via GitHub Pages, Vercel, or any static host.

## Deploying the Static API

The `api/v1/` directory can be served from any static file host. JSON files are versioned in git, so every scraper run produces a reproducible snapshot of threat data.
