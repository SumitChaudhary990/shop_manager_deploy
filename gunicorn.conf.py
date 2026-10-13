import os

# Automatically bind to Render's dynamic PORT (defaults to 5000 for local)
port = os.environ.get("PORT", "5000")
bind = f"0.0.0.0:{port}"

# Worker configuration optimized for Render free/starter tiers
workers = 2
threads = 4
timeout = 120
keepalive = 5
