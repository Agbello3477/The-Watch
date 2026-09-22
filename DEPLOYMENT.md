# 🚀 The Watch: Production Deployment Guide

Follow this 3-step deployment guide to deploy **The Watch** across **Neon (Database)**, **Render (Backend API)**, and **Vercel (Frontend Dashboard)**.

---

## Step 1: Provision Serverless PostgreSQL on Neon

1. Go to [Neon.tech](https://neon.tech) and create a new project named **`the-watch-db`**.
2. Under **Dashboard -> Connection Details**, copy the **Connection string**.
   It looks like:
   ```text
   postgresql://[user]:[password]@[endpoint].neon.tech/neondb?sslmode=require
   ```
3. *(Optional for high-throughput pooling)*: Toggle on **Connection Pooling** to get the pgBouncer pooled endpoint:
   ```text
   postgresql://[user]:[password]@[endpoint]-pooler.neon.tech/neondb?sslmode=require&pgbouncer=true
   ```
4. Keep this connection string ready for Step 2.

> **Note**: When The Watch backend boots up for the first time, it will **automatically execute the database schema migrations (`schema.sql`)** and seed the default institutional tenants (`NOUN-HRMS`, `Clinic-EHR`, `Security-Dispatch`).

---

## Step 2: Deploy Backend API on Render

1. Go to [Render Dashboard](https://dashboard.render.com) -> Click **New +** -> **Web Service**.
2. Connect your GitHub repository: **`Agbello3477/The-Watch`**.
3. Configure the Web Service settings:
   - **Name**: `the-watch-backend`
   - **Region**: `Frankfurt (EU Central)` *(Recommended for low latency to Nigeria & Europe)*
   - **Branch**: `main`
   - **Root Directory**: `backend`
   - **Runtime**: `Node`
   - **Build Command**: `npm install && npm run build`
   - **Start Command**: `npm start`
   - **Instance Type**: `Free` or `Starter`
4. Under **Environment Variables**, add:
   | Key | Value | Notes |
   | :--- | :--- | :--- |
   | `NODE_ENV` | `production` | Enables production mode |
   | `DATABASE_URL` | `postgresql://...` | Paste your **Neon** connection string from Step 1 |
   | `NODE_OPTIONS` | `--max-old-space-size=512` | Prevents V8 memory exhaustion |
   | `HMAC_SECRET` | `the-watch-enterprise-hmac-master-key-2026` | Any secure 32+ character key |
5. Click **Create Web Service**.
6. Once deployed, Render will provide your public backend URL, for example:
   ```text
   https://the-watch-backend.onrender.com
   ```

---

## Step 3: Deploy Frontend Dashboard on Vercel

1. Go to [Vercel Dashboard](https://vercel.com/dashboard) -> Click **Add New...** -> **Project**.
2. Select your repository: **`Agbello3477/The-Watch`**.
3. In the project setup screen:
   - **Framework Preset**: `Vite`
   - **Root Directory**: Click *Edit* and select **`frontend`**
   - **Build Command**: `npm run build` *(default)*
   - **Output Directory**: `dist` *(default)*
4. Under **Environment Variables**, add:
   | Key | Value |
   | :--- | :--- |
   | `VITE_API_URL` | `https://the-watch-backend.onrender.com` *(Paste your Render backend URL from Step 2)* |
5. Click **Deploy**.
6. Vercel will build and assign your live production dashboard URL (e.g. `https://the-watch.vercel.app`).

---

## Step 4: Verify Full Production Connectivity

1. Open your live Vercel URL in your browser.
2. Verify:
   - The **Platform Health Score** loads from the Neon PostgreSQL database.
   - The **Global Threat Radar Map** displays active institutional nodes.
   - Go to the **Attack Simulator** tab -> Click **"Fire Vector"** to test live real-time incident detection in production.
   - Go to **Forensic Reports (PDF/CSV)** -> Click **"Download Audit PDF"** to verify executive report generation.

---

## 🛡️ Sentinel Agent Host Integration (NOUN-HRMS)

Once deployed, your host applications can ship telemetry to your production watchdog by mounting the 3-line middleware:

```typescript
import express from 'express';
import { createSentinelMiddleware } from '@the-watch/sentinel-agent';

const app = express();

app.use(createSentinelMiddleware({
  systemId: 'NOUN-HRMS',
  apiKey: 'tel_sec_noun_hrms_98234',
  apiSecret: 'sec_sig_noun_8849204',
  endpoint: 'https://the-watch-backend.onrender.com/api/v1/telemetry/ingest',
  transport: 'HTTP',
}));
```
