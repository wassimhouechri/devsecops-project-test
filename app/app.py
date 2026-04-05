from flask import Flask, jsonify, request, abort
from functools import wraps
import time
import os

app = Flask(__name__)

# ─── Security Headers (CSP, HSTS, X-Frame-Options, etc.) ───
@app.after_request
def set_security_headers(response):
    response.headers["Content-Security-Policy"] = (
        "default-src 'none'; frame-ancestors 'none'"
    )
    response.headers["Strict-Transport-Security"] = (
        "max-age=31536000; includeSubDomains"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    # Remove server fingerprint
    response.headers.pop("Server", None)
    return response


# ─── Rate Limiting ───
# IMPORTANT : Ce rate limiter est SIMPLE et fonctionne uniquement pour du test / un seul pod
# Il utilise un dictionnaire en mémoire (_rate_store) → ne scale PAS en production

RATE_LIMIT = int(os.environ.get("RATE_LIMIT", "60"))   # nombre max de requêtes
RATE_WINDOW = int(os.environ.get("RATE_WINDOW", "60")) # fenêtre en secondes (ex: 60 = 1 minute)

# TODO en production : utiliser Redis ou un rate limiter distribué
# Recommandation : flask-limiter + Redis (ou RedisRateLimiter)
# Le dict en mémoire ne fonctionne pas avec plusieurs replicas Kubernetes
# car chaque pod a son propre dictionnaire → un utilisateur peut dépasser la limite en changeant de pod.

_rate_store: dict = {}

def rate_limited(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        ip = request.remote_addr or "unknown"
        now = time.time()
        window_start = now - RATE_WINDOW

        # Purge old entries
        _rate_store[ip] = [t for t in _rate_store.get(ip, []) if t > window_start]

        if len(_rate_store[ip]) >= RATE_LIMIT:
            abort(429)

        _rate_store[ip].append(now)
        return f(*args, **kwargs)
    return decorated


# ─── API Key Auth (read from env, never hardcoded) ───
API_KEY = os.environ.get("API_KEY", "")

def require_api_key(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not API_KEY:
            # If no key configured, auth is disabled (dev mode)
            return f(*args, **kwargs)
        key = request.headers.get("X-API-Key", "")
        if key != API_KEY:
            abort(401)
        return f(*args, **kwargs)
    return decorated


# ─── Routes ───
@app.route("/")
@rate_limited
def home():
    return jsonify({"status": "ok", "message": "DevSecOps app running"})


@app.route("/health")
def health():
    return jsonify({"status": "healthy"}), 200


@app.route("/api/data")
@rate_limited
@require_api_key
def data():
    return jsonify({"data": [1, 2, 3], "count": 3})


# ─── Custom error handlers ───
@app.errorhandler(401)
def unauthorized(e):
    return jsonify({"error": "Unauthorized"}), 401

@app.errorhandler(429)
def too_many_requests(e):
    return jsonify({"error": "Too Many Requests"}), 429


if __name__ == "__main__":
    # Never run debug=True in production
    app.run(host="0.0.0.0", port=5000, debug=False)
