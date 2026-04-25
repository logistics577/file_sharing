# main.py
# FastAPI Single File - Production Style UI
# pip install fastapi uvicorn python-multipart
# uvicorn main:app --reload

import os
import sqlite3
import shutil
import secrets
from datetime import datetime

from fastapi import FastAPI, UploadFile, File, Form
from fastapi.responses import HTMLResponse, RedirectResponse, FileResponse

app = FastAPI(title="Secure Vault")

# ----------------------------
# SAFE PATHS
# ----------------------------
BASE_DIR = "/tmp"
UPLOAD_DIR = "/tmp/uploads"
ENV_DIR = "/tmp/envfiles"
DB_FILE = "/tmp/vault.db"

os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(ENV_DIR, exist_ok=True)


# ----------------------------
# DATABASE
# ----------------------------
def db():
    conn = sqlite3.connect(DB_FILE, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = db()

    conn.execute("""
    CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        password TEXT UNIQUE
    )
    """)

    conn.execute("""
    CREATE TABLE IF NOT EXISTS files(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        file_name TEXT,
        saved_name TEXT,
        created_at TEXT
    )
    """)

    conn.execute("""
    CREATE TABLE IF NOT EXISTS links(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        url TEXT,
        created_at TEXT
    )
    """)

    conn.execute("""
    CREATE TABLE IF NOT EXISTS envfiles(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        file_name TEXT,
        created_at TEXT
    )
    """)

    conn.commit()
    conn.close()


init_db()


# ----------------------------
# HELPERS
# ----------------------------
def get_user(password):
    conn = db()
    row = conn.execute(
        "SELECT * FROM users WHERE password=?",
        (password,)
    ).fetchone()
    conn.close()
    return row


def make_password():
    while True:
        pwd = str(secrets.randbelow(900000) + 100000)
        if not get_user(pwd):
            conn = db()
            conn.execute(
                "INSERT INTO users(password) VALUES(?)",
                (pwd,)
            )
            conn.commit()
            conn.close()
            return pwd


# ----------------------------
# COMMON CSS
# ----------------------------
CSS = """
<style>
*{
margin:0;
padding:0;
box-sizing:border-box;
font-family:Inter,Arial,sans-serif;
}
body{
background:linear-gradient(135deg,#0f172a,#111827);
min-height:100vh;
padding:40px;
color:white;
}
.card{
max-width:900px;
margin:auto;
background:rgba(255,255,255,.08);
backdrop-filter:blur(14px);
padding:28px;
border-radius:18px;
box-shadow:0 20px 60px rgba(0,0,0,.3);
}
h1,h2,h3{
margin-bottom:18px;
}
input,textarea{
width:100%;
padding:14px;
border:none;
outline:none;
border-radius:12px;
margin-top:10px;
background:#ffffff12;
color:white;
}
textarea{
min-height:140px;
resize:vertical;
}
button{
width:100%;
padding:14px;
border:none;
border-radius:12px;
margin-top:12px;
background:#2563eb;
color:white;
font-weight:700;
cursor:pointer;
transition:.2s;
}
button:hover{
transform:translateY(-2px);
background:#1d4ed8;
}
.grid{
display:grid;
grid-template-columns:1fr 1fr;
gap:20px;
margin-top:20px;
}
table{
width:100%;
border-collapse:collapse;
margin-top:16px;
background:#ffffff08;
border-radius:12px;
overflow:hidden;
}
th,td{
padding:12px;
border-bottom:1px solid #ffffff15;
text-align:left;
}
a{
color:#93c5fd;
text-decoration:none;
}
.bad{
background:#dc2626;
}
.msg{
margin-top:14px;
padding:12px;
border-radius:12px;
background:#dc262620;
color:#fecaca;
}
.ok{
background:#16a34a20;
color:#bbf7d0;
}
small{
color:#cbd5e1;
}
</style>
"""


# ----------------------------
# HOME
# ----------------------------
@app.get("/", response_class=HTMLResponse)
def home(msg: str = ""):
    message = f'<div class="msg">{msg}</div>' if msg else ""

    return f"""
    <html>
    <head>{CSS}</head>
    <body>
    <div class="card" style="max-width:520px">
        <h1>Secure Vault</h1>
        <small>Create password or login</small>

        {message}

        <form method="post" action="/create-password">
            <button>Create 6 Digit Password</button>
        </form>

        <br>

        <form method="post" action="/login">
            <input name="password" placeholder="Enter 6 digit password" required>
            <button>Open Vault</button>
        </form>
    </div>
    </body>
    </html>
    """


# ----------------------------
# CREATE PASSWORD
# ----------------------------
@app.post("/create-password", response_class=HTMLResponse)
def create_password():
    pwd = make_password()

    return f"""
    <html>
    <head>{CSS}</head>
    <body>
    <div class="card" style="max-width:520px">
        <h2>Password Created</h2>
        <h1>{pwd}</h1>
        <small>Share this password to access same vault.</small>

        <form method="post" action="/login">
            <input type="hidden" name="password" value="{pwd}">
            <button>Open Dashboard</button>
        </form>

        <br>
        <a href="/">Back</a>
    </div>
    </body>
    </html>
    """


# ----------------------------
# LOGIN
# ----------------------------
@app.post("/login")
def login(password: str = Form(...)):
    user = get_user(password)
    if not user:
        return RedirectResponse(
            url="/?msg=Wrong Password",
            status_code=303
        )

    return RedirectResponse(
        url=f"/dashboard?password={password}",
        status_code=303
    )


# ----------------------------
# DASHBOARD
# ----------------------------
@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(password: str):
    user = get_user(password)
    if not user:
        return RedirectResponse(url="/?msg=Session Expired")

    conn = db()

    files = conn.execute(
        "SELECT * FROM files WHERE user_id=? ORDER BY id DESC",
        (user["id"],)
    ).fetchall()

    links = conn.execute(
        "SELECT * FROM links WHERE user_id=? ORDER BY id DESC",
        (user["id"],)
    ).fetchall()

    envs = conn.execute(
        "SELECT * FROM envfiles WHERE user_id=? ORDER BY id DESC",
        (user["id"],)
    ).fetchall()

    conn.close()

    file_rows = ""
    for f in files:
        file_rows += f"""
        <tr>
        <td>{f["file_name"]}</td>
        <td><a href="/download/{f['id']}?password={password}">Download</a></td>
        <td><a href="/delete-file/{f['id']}?password={password}">Delete</a></td>
        </tr>
        """

    link_rows = ""
    for l in links:
        link_rows += f"""
        <tr>
        <td><a href="{l["url"]}" target="_blank">{l["url"]}</a></td>
        <td><a href="/delete-link/{l['id']}?password={password}">Delete</a></td>
        </tr>
        """

    env_rows = ""
    for e in envs:
        env_rows += f"""
        <tr>
        <td>{e["file_name"]}</td>
        <td>{e["created_at"]}</td>
        </tr>
        """

    return f"""
    <html>
    <head>{CSS}</head>
    <body>
    <div class="card">

        <h1>Dashboard</h1>
        <small>Password: {password}</small>

        <div class="grid">

            <div>
                <h3>Upload File</h3>
                <form method="post" action="/upload" enctype="multipart/form-data">
                    <input type="hidden" name="password" value="{password}">
                    <input type="file" name="file" required>
                    <button>Upload</button>
                </form>

                <h3 style="margin-top:20px">Save URL</h3>
                <form method="post" action="/add-link">
                    <input type="hidden" name="password" value="{password}">
                    <input name="url" placeholder="https://example.com" required>
                    <button>Save URL</button>
                </form>
            </div>

            <div>
                <h3>Create .env File</h3>
                <form method="post" action="/add-env">
                    <input type="hidden" name="password" value="{password}">
                    <textarea name="content" placeholder="DB_URL=...
API_KEY=..."></textarea>
                    <button>Create Random env.txt</button>
                </form>
            </div>

        </div>

        <h3 style="margin-top:30px">Files</h3>
        <table>
            <tr><th>Name</th><th>Download</th><th>Delete</th></tr>
            {file_rows}
        </table>

        <h3 style="margin-top:30px">Links</h3>
        <table>
            <tr><th>URL</th><th>Delete</th></tr>
            {link_rows}
        </table>

        <h3 style="margin-top:30px">Generated Env Files</h3>
        <table>
            <tr><th>File</th><th>Created</th></tr>
            {env_rows}
        </table>

    </div>
    </body>
    </html>
    """


# ----------------------------
# FILE UPLOAD
# ----------------------------
@app.post("/upload")
def upload(password: str = Form(...), file: UploadFile = File(...)):
    user = get_user(password)
    if not user:
        return RedirectResponse("/")

    name = secrets.token_hex(8) + "_" + file.filename
    path = os.path.join(UPLOAD_DIR, name)

    with open(path, "wb") as f:
        shutil.copyfileobj(file.file, f)

    conn = db()
    conn.execute(
        "INSERT INTO files(user_id,file_name,saved_name,created_at) VALUES(?,?,?,?)",
        (user["id"], file.filename, name, datetime.utcnow().isoformat())
    )
    conn.commit()
    conn.close()

    return RedirectResponse(f"/dashboard?password={password}", 303)


# ----------------------------
# DOWNLOAD
# ----------------------------
@app.get("/download/{fid}")
def download(fid: int, password: str):
    user = get_user(password)
    if not user:
        return RedirectResponse("/")

    conn = db()
    row = conn.execute(
        "SELECT * FROM files WHERE id=? AND user_id=?",
        (fid, user["id"])
    ).fetchone()
    conn.close()

    if not row:
        return RedirectResponse(f"/dashboard?password={password}")

    path = os.path.join(UPLOAD_DIR, row["saved_name"])

    return FileResponse(path, filename=row["file_name"])


# ----------------------------
# DELETE FILE
# ----------------------------
@app.get("/delete-file/{fid}")
def delete_file(fid: int, password: str):
    user = get_user(password)
    if not user:
        return RedirectResponse("/")

    conn = db()
    row = conn.execute(
        "SELECT * FROM files WHERE id=? AND user_id=?",
        (fid, user["id"])
    ).fetchone()

    if row:
        p = os.path.join(UPLOAD_DIR, row["saved_name"])
        if os.path.exists(p):
            os.remove(p)

        conn.execute("DELETE FROM files WHERE id=?", (fid,))
        conn.commit()

    conn.close()
    return RedirectResponse(f"/dashboard?password={password}", 303)


# ----------------------------
# SAVE LINK
# ----------------------------
@app.post("/add-link")
def add_link(password: str = Form(...), url: str = Form(...)):
    user = get_user(password)
    if not user:
        return RedirectResponse("/")

    conn = db()
    conn.execute(
        "INSERT INTO links(user_id,url,created_at) VALUES(?,?,?)",
        (user["id"], url.strip(), datetime.utcnow().isoformat())
    )
    conn.commit()
    conn.close()

    return RedirectResponse(f"/dashboard?password={password}", 303)


# ----------------------------
# DELETE LINK
# ----------------------------
@app.get("/delete-link/{lid}")
def delete_link(lid: int, password: str):
    user = get_user(password)
    if not user:
        return RedirectResponse("/")

    conn = db()
    conn.execute(
        "DELETE FROM links WHERE id=? AND user_id=?",
        (lid, user["id"])
    )
    conn.commit()
    conn.close()

    return RedirectResponse(f"/dashboard?password={password}", 303)


# ----------------------------
# CREATE ENV FILE
# ----------------------------
@app.post("/add-env")
def add_env(password: str = Form(...), content: str = Form(...)):
    user = get_user(password)
    if not user:
        return RedirectResponse("/")

    random_name = f"env_{secrets.token_hex(6)}.txt"
    path = os.path.join(ENV_DIR, random_name)

    with open(path, "w", encoding="utf-8") as f:
        f.write(content)

    conn = db()
    conn.execute(
        "INSERT INTO envfiles(user_id,file_name,created_at) VALUES(?,?,?)",
        (user["id"], random_name, datetime.utcnow().isoformat())
    )
    conn.commit()
    conn.close()

    return RedirectResponse(f"/dashboard?password={password}", 303)
