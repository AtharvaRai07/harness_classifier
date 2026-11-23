# Harness Engineering classifier — deployment

Files:
- `classifier.py` — the deterministic rule engine (requestDecision/toolDecision/route/trajectory)
- `app.py` — FastAPI wrapper exposing `POST /classify`
- `test_cases.py` — 12 hand-labeled sanity checks (`python3 test_cases.py`)
- `requirements.txt`, `Dockerfile` — for deployment

## Fastest path: Render.com (free)
1. Push this folder to a new GitHub repo (or use Render's "Upload" flow).
2. render.com -> New -> Web Service -> connect the repo.
3. Build command: `pip install -r requirements.txt`
   Start command: `uvicorn app:app --host 0.0.0.0 --port $PORT`
4. Deploy. Render gives you `https://<name>.onrender.com`.
5. Your POST route for the assignment's "Public HTTPS endpoint URL" field:
   `https://<name>.onrender.com/classify`

## Alternative: Railway.app
Same start command (`uvicorn app:app --host 0.0.0.0 --port $PORT`), Railway
auto-detects `$PORT`.

## Alternative: Fly.io (uses the included Dockerfile)
```
fly launch        # accept defaults, it detects the Dockerfile
fly deploy
```
URL will be `https://<app-name>.fly.dev/classify`.

## Local test before deploying
```
pip install -r requirements.txt
uvicorn app:app --host 0.0.0.0 --port 8000
# in another terminal:
python3 test_cases.py
curl -X POST http://localhost:8000/classify -H "Content-Type: application/json" -d '{"cases":[...]}'
```

Note: Render/Railway free tiers can cold-sleep after inactivity, which may
blow the 60s-per-request budget on the *first* request after idling. If your
Check calls fail with a timeout on the first batch, hit the health endpoint
(`GET /`) a minute before you click Check to warm it up, or upgrade to a
paid "always-on" tier for the actual Save.
