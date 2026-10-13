import os

# Render dynamically sets PORT (defaults to 10000 on Render)
port = os.environ.get("PORT", "10000")
bind = f"0.0.0.0:{port}"

# Production worker settings for Render
workers = 2
threads = 4
worker_class = "gthread"
timeout = 120
keepalive = 5
