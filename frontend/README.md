# AUTO-RECON AI — Frontend Web Application

Browser-based automotive digital forensics and kinematic incident reconstruction interface.

GitHub Repository: [https://github.com/Vatsa-47/Auto-Recon-AI](https://github.com/Vatsa-47/Auto-Recon-AI)

---

## Architecture Overview

This directory contains the standalone, production-ready frontend for AUTO-RECON AI.
It is built using pure modern web standards:
- **HTML5 Canvas Kinematics**: High-performance multi-camera 2D simulation (Top View, Dashcam, Follower).
- **Tailwind CSS & FontAwesome**: Modern cyber-forensic interface styling.
- **Chart.js**: Real-time synchronized CAN telemetry graphs (Speed, Brake Bar, Steering Angle, Yaw Rate).
- **Client-Side SHA-256 (Web Crypto API)**: Client-side cryptographic evidence hashing and tamper verification.
- **Configurable Backend Integration**: Flexible API layer that communicates with the FastAPI + PyTorch backend when online, and runs self-contained with offline curated forensic cases when offline.

---

## Files Included

| File | Purpose |
| :--- | :--- |
| `index.html` | Core single-page application dashboard layout and modal containers. |
| `config.js` | Configurable API base URL manager for local development and cloud production. |
| `app.js` | Forensic state machine, canvas renderers, telemetry playback engine, and API client. |
| `styles.css` | Custom forensic workbench styling, animation keyframes, and layout overrides. |
| `sample-data.js` | Curated baseline incidents, vehicle profiles, pre-crash CAN logs, and presentation slides. |
| `vercel.json` | Vercel static deployment configuration and security headers. |
| `auto_recon_synthetic_angle_crash.csv` | Sample telemetry CSV dataset for user upload testing. |
| `auto_recon_synthetic_angle_crash.json` | Sample telemetry JSON dataset for user upload testing. |

---

## Deploying to Vercel

### Method A: Deploy from GitHub (Recommended)
1. Go to [Vercel](https://vercel.com) and click **"Add New Project"**.
2. Import the repository: `https://github.com/Vatsa-47/Auto-Recon-AI`.
3. Under **Project Settings**:
   - **Framework Preset**: `Other`
   - **Root Directory**: `frontend` (or leave default if using root `vercel.json`)
4. Click **Deploy**.

### Method B: Deploy using Vercel CLI
```bash
cd frontend
vercel deploy --prod
```

---

## Configuring the Backend API URL

`config.js` is loaded before `app.js` and provides 3 seamless ways to connect your deployed frontend to a backend:

### 1. In `frontend/config.js` (Permanent Production URL)
Once your backend is hosted (e.g. on Railway, Render, Fly.io, Google Cloud Run, AWS), set the `PRODUCTION_API` constant in `frontend/config.js`:
```javascript
const PRODUCTION_API = "https://your-backend-service.up.railway.app/api";
```

### 2. Via URL Query Parameter (Instant Testing / Staging)
You can point any deployment instance to any live backend URL without redeploying:
```
https://your-app.vercel.app/?api=https://your-backend-service.up.railway.app/api
```

### 3. Local Development Default
When running on `localhost` or `127.0.0.1`, `config.js` automatically routes to:
```
http://127.0.0.1:8000/api
```

### Offline / Demo Mode
If the backend is not reachable or offline, the interface automatically detects this via `checkBackendHealth()` and operates in **Local Forensic Mode** using built-in curated cases and Web Crypto SHA-256 hashing.
