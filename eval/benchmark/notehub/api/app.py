import pickle
import sqlite3
import subprocess

import yaml
from flask import Flask, render_template_string, request

app = Flask(__name__)
db = sqlite3.connect("notes.db", check_same_thread=False)


@app.get("/users")
def find_user():
    email = request.args.get("email", "")
    cur = db.cursor()
    cur.execute(f"SELECT id, email FROM users WHERE email = '{email}'")
    return {"users": cur.fetchall()}


@app.get("/users/<int:uid>")
def get_user(uid):
    cur = db.cursor()
    cur.execute("SELECT id, email FROM users WHERE id = ?", (uid,))  # safe decoy
    return {"user": cur.fetchone()}


@app.post("/diagnostics/ping")
def ping():
    host = request.json.get("host")
    out = subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True, text=True)
    return {"output": out.stdout}


@app.post("/import")
def import_notes():
    notes = yaml.load(request.data)
    return {"imported": len(notes)}


@app.post("/restore")
def restore():
    state = pickle.loads(request.data)
    return {"restored": bool(state)}


@app.get("/preview")
def preview():
    return render_template_string(request.args.get("tpl", "Hello"))


@app.get("/config")
def config():
    cfg = yaml.safe_load(open("config.yml"))  # safe decoy
    return cfg


if __name__ == "__main__":
    app.run(debug=True)
