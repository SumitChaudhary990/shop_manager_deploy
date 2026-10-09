# 🚀 Live Deployment Guide — Shop Management System

This folder is **100% self-contained and pre-configured** for live deployment to any cloud hosting provider, VPS, Docker container, or local store network (LAN).

---

## 📁 Package Contents

```text
shop_manager_deploy/
├── app.py                  # Core Flask backend with role auth, billing, & security
├── wsgi.py                 # Production WSGI entry point (Gunicorn / uWSGI / Waitress)
├── requirements.txt        # Production Python dependencies
├── Procfile                # Cloud process file (Render, Railway, Heroku)
├── render.yaml             # Render 1-click cloud blueprint
├── Dockerfile              # Production container build specification
├── .dockerignore           # Excluded container build files
├── .gitignore              # Git ignore rules
├── .env.example            # Environment variables template
├── run_app.bat             # 1-Click launcher for Windows / Local PC
├── run_app.sh              # 1-Click launcher for Linux / Mac / VPS
├── inventory.json          # Seed stock inventory
├── users.json              # Default Admin & Staff credentials
├── security_config.json    # Master Recovery PIN & security thresholds
├── security_audit.json     # Live audit event log
├── bills/                  # Bill storage directory
├── templates/              # All 14 HTML UI templates
└── DEPLOYMENT_GUIDE.md     # This comprehensive deployment guide
```

---

## 🔑 Initial Default Credentials

| Role | Username | Password | Purpose |
|---|---|---|---|
| **Admin** | `admin` | `admin123` | Full access: User creation, role assignment, password viewing, revenue stats |
| **Staff** | `staff` | `staff123` | Cashier terminal: POS billing, item lookup, bill search |

> 🔒 **Master Recovery PIN**: `778899` (used by Admin if admin password is ever forgotten). Can be changed inside Admin Dashboard -> Security Center.

---

## 🌐 Method 1: Deploy Free on Render.com (Recommended & Easiest)

Render gives you a free HTTPS live URL (e.g., `https://your-shop.onrender.com`).

### Steps:
1. Push this folder to a GitHub repository:
   ```bash
   git init
   git add .
   git commit -m "Initial shop deployment"
   git branch -M main
   git remote add origin https://github.com/YOUR_USERNAME/YOUR_REPO.git
   git push -u origin main
   ```
2. Go to **[https://render.com](https://render.com)** and create a free account.
3. Click **New +** -> **Web Service**.
4. Connect your GitHub repository.
5. Render will automatically detect the settings from `render.yaml` or fill in:
   - **Environment**: `Python 3`
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `gunicorn wsgi:app`
6. Click **Create Web Service**.
7. In 1–2 minutes, your shop will be live at `https://your-service-name.onrender.com`!

---

## 🚂 Method 2: Deploy on Railway.app

1. Go to **[https://railway.app](https://railway.app)** and log in with GitHub.
2. Click **New Project** -> **Deploy from GitHub repo**.
3. Select this repository.
4. Railway automatically detects `Procfile` / `Dockerfile` and builds the service.
5. Under service settings, click **Generate Domain** to get your public `.up.railway.app` URL.

---

## 🐍 Method 3: Deploy on PythonAnywhere

1. Create a free account at **[https://www.pythonanywhere.com](https://www.pythonanywhere.com)**.
2. Open the **Bash Console** and clone/upload your files into a directory (e.g. `/home/yourusername/shop_manager`).
3. Create a virtual environment and install dependencies:
   ```bash
   mkvirtualenv --python=/usr/bin/python3.10 shop-venv
   pip install -r requirements.txt
   ```
4. Go to the **Web** tab -> **Add a new web app** -> Choose **Manual configuration** (Python 3.10).
5. Under **Virtualenv**, set path to:
   `/home/yourusername/.virtualenvs/shop-venv`
6. Click on your **WSGI configuration file** link, replace its content with:
   ```python
   import sys
   import os

   path = '/home/yourusername/shop_manager'
   if path not in sys.path:
       sys.path.append(path)

   from wsgi import app as application
   ```
7. Click **Reload** at the top of the Web tab. Your app is live at `yourusername.pythonanywhere.com`.

---

## 🐳 Method 4: Deploy with Docker (Any VPS or Cloud)

A multi-stage, hardened `Dockerfile` is included:

```bash
# 1. Build the container image
docker build -t shop-manager .

# 2. Run the container on port 5000 with a persistent data volume
docker run -d \
  --name my-shop \
  -p 5000:5000 \
  -e SECRET_KEY="my-production-secret-key-xyz" \
  -v shop_data:/app/bills \
  shop-manager
```
Access at `http://your-server-ip:5000`.

---

## 🖥️ Method 5: Local Store LAN / Wi-Fi Multi-Device Setup

If you want to run this in a physical store without paying for hosting, you can run it on your main counter PC and allow **all phones, tablets, and laptops in the store** to access it simultaneously!

1. Double-click `run_app.bat` on the main PC.
2. Find the main PC's local IP address:
   - Press `Win + R`, type `cmd`, hit Enter.
   - Run `ipconfig` and note down your **IPv4 Address** (e.g. `192.168.1.15`).
3. On any phone, tablet, or cashier laptop connected to the same shop Wi-Fi, open the browser and type:
   ```text
   http://192.168.1.15:5000
   ```
4. Cashiers can now log in, generate bills, look up inventory, and print receipts directly from their devices!

---

## ⚙️ Environment Variables (Optional)

You can set these in your hosting dashboard or in a `.env` file:

| Variable | Default | Description |
|---|---|---|
| `SECRET_KEY` | `shop-mgmt-secure-session-key-2026` | Cryptographic secret for signing session cookies. |
| `PORT` | `5000` | Port for the web server to listen on. |
| `FLASK_ENV` | `production` | Set to `development` for local debugging only. |

---

## 💡 Post-Deployment Checklist

- [ ] Log in as `admin` (`admin123`).
- [ ] Go to **Admin Dashboard -> User Accounts** and change the admin password.
- [ ] Go to **Security Center -> Master Security PIN** and set a new 6-digit recovery PIN.
- [ ] Create staff cashier accounts for your employees.
- [ ] Add your store's inventory items in **Inventory Management**.
- [ ] Verify receipt printing via **POS Billing**.
