# ⚠️  FICHIER DE TEST UNIQUEMENT — NE JAMAIS DEPLOYER EN PRODUCTION
# Ce fichier contient des vulnérabilités intentionnelles pour valider
# que chaque outil du pipeline les détecte correctement.

from flask import Flask, request, jsonify
import sqlite3
import subprocess
import os
import pickle
import hashlib

app = Flask(__name__)

# ─── VULN 1 : Secret hardcodé (détecté par Gitleaks) ───
SECRET_KEY   = "super_secret_password_1234"
AWS_API_KEY  = "AKIAIOSFODNN7EXAMPLE"
DB_PASSWORD  = "admin123"

# ─── VULN 2 : debug=True (détecté par Semgrep + Bandit) ───
# Expose la console interactive Werkzeug — exécution de code arbitraire

# ─── VULN 3 : Injection SQL (détecté par Bandit + Semgrep) ───
@app.route("/user")
def get_user():
    username = request.args.get("username", "")
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # VULNERABLE: concaténation directe dans la requête SQL
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    rows = cursor.fetchall()
    return jsonify(rows)

# ─── VULN 4 : Injection de commande OS (détecté par Bandit + Semgrep) ───
@app.route("/ping")
def ping():
    host = request.args.get("host", "localhost")
    # VULNERABLE: shell=True + entrée utilisateur non validée
    result = subprocess.run(
        "ping -c 1 " + host,
        shell=True,
        capture_output=True,
        text=True
    )
    return jsonify({"output": result.stdout})

# ─── VULN 5 : Désérialisation non sécurisée (détecté par Bandit) ───
@app.route("/load", methods=["POST"])
def load_data():
    # VULNERABLE: pickle.loads sur données non fiables = RCE
    data = request.get_data()
    obj = pickle.loads(data)
    return jsonify({"loaded": str(obj)})

# ─── VULN 6 : Path traversal (détecté par Semgrep) ───
@app.route("/file")
def read_file():
    filename = request.args.get("name", "")
    # VULNERABLE: permet de lire /etc/passwd avec name=../../etc/passwd
    with open("/app/data/" + filename, "r") as f:
        return f.read()

# ─── VULN 7 : Mot de passe haché avec MD5 (détecté par Bandit) ───
@app.route("/hash")
def hash_password():
    password = request.args.get("password", "")
    # VULNERABLE: MD5 est cryptographiquement cassé
    hashed = hashlib.md5(password.encode()).hexdigest()
    return jsonify({"hash": hashed})

# ─── VULN 8 : Pas de validation d'entrée, pas de rate limit, pas d'auth ───
@app.route("/admin/delete")
def delete_all():
    conn = sqlite3.connect("users.db")
    conn.execute("DELETE FROM users")
    conn.commit()
    return jsonify({"status": "all users deleted"})


if __name__ == "__main__":
    # VULNERABLE: debug=True expose la console Werkzeug
    app.run(host="0.0.0.0", port=5000, debug=True)
