# NEXUS Relay Server

Central relay that all PCs connect to. One URL controls everything.

## Deploy to Render.com (FREE)

1. Create a **GitHub repo** and push the `server/` folder contents to it
2. Go to [render.com](https://render.com) → Sign up (free)
3. **New** → **Web Service** → Connect your GitHub repo
4. Settings:
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `gunicorn app:app --bind 0.0.0.0:$PORT --workers 4 --threads 4`
5. Add **Environment Variables**:
   - `DASH_USER` = your dashboard username
   - `DASH_PASS` = your dashboard password  
   - `RELAY_SECRET` = a secret key (must match the payload's RELAY_SECRET)
6. Deploy → you get a URL like `https://nexus-relay.onrender.com`

## Configure Payloads

In each PC's `main.py`, set:
```python
RELAY_URL = "https://nexus-relay.onrender.com"  # your Render URL
RELAY_SECRET = "your-secret-key"                 # must match server env var
```

## How It Works

- Each PC sends heartbeats every 15s to register itself
- Dashboard shows all connected machines with live status
- Click a machine to select it, then use any command
- "Broadcast" sends a command to ALL machines at once
- Video streaming: click "Start Stream" to see live screen/webcam
- Interactive mode: click/type on the stream to control remotely

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DASH_USER` | `admin` | Dashboard login username |
| `DASH_PASS` | `admin123` | Dashboard login password |
| `RELAY_SECRET` | `changeme-secret-key` | Shared secret between server and payloads |
| `SECRET_KEY` | (auto-generated) | Flask session secret |
