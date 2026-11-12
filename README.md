# SentinelAI API (single file, Render-ready)

Endpoints: `POST /v1/scan` (leaked secrets and personal data), `POST /v1/headers/analyze` (security-header grade),
`GET /v1/rules`, `GET /health`. Interactive docs at `/docs` unless `ENABLE_DOCS=false`.

## Files (keep all of them at the root of your GitHub repo)
```
main.py            the whole API
requirements.txt   fastapi, uvicorn, pydantic
.python-version    tells Render to use Python 3.12.3
.gitignore
README.md
```

## Deploy on Render (no Docker)
1. Push these files to a GitHub repository.
2. Render dashboard: **New > Web Service**, connect the repo.
3. Fill in:
   - **Language:** Python 3
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:** `uvicorn main:app --host 0.0.0.0 --port $PORT`
   - **Instance Type:** Starter or higher (the Free type sleeps, so the first call is very slow)
   - **Health Check Path:** `/health`
4. Under **Environment Variables** add:
   - `ENVIRONMENT` = `production`
   - `RAPIDAPI_PROXY_SECRET` = the secret from RapidAPI (use any long random text for now if you do not have it yet, then replace it)
   - `ENABLE_DOCS` = `false`
5. Click **Create Web Service**.

## Check it works
- Open `https://YOUR-SERVICE.onrender.com/health`. It should show `{"status":"ok","version":"1.0.0"}`.
- Calling `/v1/scan` without the secret header returns `401`. With it:
```bash
curl -X POST https://YOUR-SERVICE.onrender.com/v1/scan \
  -H "Content-Type: application/json" \
  -H "X-RapidAPI-Proxy-Secret: YOUR_SECRET" \
  -d '{"content": "contact jane.doe@example.com"}'
```

## RapidAPI
Use your Render URL as the base URL. Save `https://YOUR-SERVICE.onrender.com/openapi.json` as a file and import it
into RapidAPI. Copy the value of `X-RapidAPI-Proxy-Secret` from the API's gateway/firewall settings into the
`RAPIDAPI_PROXY_SECRET` variable on Render. Plans and prices ($49, $149, $399) are configured in RapidAPI, not in code.

## Run locally
```bash
pip install -r requirements.txt
uvicorn main:app --reload
```
