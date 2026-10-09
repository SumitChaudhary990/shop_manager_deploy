"""
WSGI Entrypoint for Production Deployment
Works with Gunicorn, uWSGI, Waitress, PythonAnywhere, etc.
"""
from app import app

if __name__ == "__main__":
    app.run()
