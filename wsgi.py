"""
WSGI Entrypoint for Production Deployment
Works with Gunicorn, uWSGI, Waitress, PythonAnywhere, Render, etc.
"""
from app import app

# Standard WSGI aliases
application = app

if __name__ == "__main__":
    app.run()
