# main.py
# Vercel-safe FastAPI single file
# pip install fastapi uvicorn python-multipart

import os
import sqlite3
import shutil
import secrets
from datetime import datetime
from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, FileResponse, PlainTextResponse

app = FastAPI(title="Vercel Safe Vault")

# -------------------------------
# ALWAYS USE /tmp on Vercel
# -------------------------------
BASE_DIR = "/tmp"
UPLOAD_DIR = "/tmp/uploads"
DB_FILE = "/tmp/vault.db"

os.makedirs(UPLOAD_DIR, exist_ok=True)


# -------------------------------
# SAFE SQLITE
# -------------------------------
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

    conn.commit()
    conn.close()


# run startup
init_db()


# -------------------------------
# HELPERS
# -------------------------------
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


# -------------------------------
# HOME
# -------------------------------
@app.get("/", response_class=HTMLResponse)
def home():
    return """
    <html>
    <body style="font-family:Arial;padding:40px;background:#f2f2f2">
    <div style="background:white;padding:30px;border-radius:10px;max-width:500px;margin:auto">
    <h2>Private Vault</h2>

    <form method="post" action="/create-password">
    <button style="width:100%;padding:12px">Create Password</button>
    </form>

    <br>

    <form method="post" action="/login">
    <input name="password" placeholder="Enter Password"
    style="width:100%;padding:10px" required>
    <br><br>
    <button style="width:100%;padding:12px">Open</button>
    </form>

    </div>
    </body>
    </html>
    """


# -------------------------------
# CREATE PASSWORD
# -------------------------------
@app.post("/create-password", response_class=HTMLResponse)
def create_password():
    pwd = make_password()
    return f"""
    <html>
    <body style="font-family:Arial;padding:40px">
    <h2>Your Password</h2>
    <h1>{pwd}</h1>
    <a href="/dashboard?password={pwd}">Open Dashboard</a>
    </body>
    </html>
    """


# -------------------------------
# LOGIN
# -------------------------------
@app.post("/login")
def login(password: str = Form(...)):
    if not get_user(password):
        return PlainTextResponse("Wrong Password")

    return RedirectResponse(
        url=f"/dashboard?password={password}",
        status_code=303
    )


# -------------------------------
# DASHBOARD
# -------------------------------
@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(password: str):
    user = get_user(password)

    if not user:
        return PlainTextResponse("Invalid Password")

    conn = db()

    files = conn.execute(
        "SELECT * FROM files WHERE user_id=? ORDER BY id DESC",
        (user["id"],)
    ).fetchall()

    links = conn.execute(
        "SELECT * FROM links WHERE user_id=? ORDER BY id DESC",
        (user["id"],)
    ).fetchall()

    conn.close()

    file_html = ""
    for f in files:
        file_html += f"""
        <tr>
        <td>{f["file_name"]}</td>
        <td>
        <a href="/download/{f['id']}?password={password}">
        Download
        </a>
        </td>
        <td>
        <a href="/delete-file/{f['id']}?password={password}">
        Delete
        </a>
        </td>
        </tr>
        """

    link_html = ""
    for l in links:
        link_html += f"""
        <tr>
        <td><a href="{l["url"]}" target="_blank">{l["url"]}</a></td>
        <td>
        <a href="/delete-link/{l['id']}?password={password}">
        Delete
        </a>
        </td>
        </tr>
        """

    return f"""
    <html>
    <body style="font-family:Arial;padding:30px;background:#f2f2f2">

    <div style="background:white;padding:30px;border-radius:10px">

    <h2>Dashboard</h2>
    <p>Password: <b>{password}</b></p>

    <h3>Upload File</h3>

    <form method="post" action="/upload"
    enctype="multipart/form-data">

    <input type="hidden" name="password" value="{password}">
    <input type="file" name="file" required>
    <br><br>
    <button>Upload</button>
    </form>

    <hr>

    <h3>Save URL</h3>

    <form method="post" action="/add-link">
    <input type="hidden" name="password" value="{password}">
    <input name="url" style="width:100%;padding:10px"
    placeholder="Paste Link" required>
    <br><br>
    <button>Save URL</button>
    </form>

    <hr>

    <h3>Files</h3>

    <table border="1" cellpadding="8">
    <tr><th>Name</th><th>Download</th><th>Delete</th></tr>
    {file_html}
    </table>

    <hr>

    <h3>Saved Links</h3>

    <table border="1" cellpadding="8">
    <tr><th>URL</th><th>Delete</th></tr>
    {link_html}
    </table>

    </div>
    </body>
    </html>
    """


# -------------------------------
# UPLOAD
# -------------------------------
@app.post("/upload")
def upload(
    password: str = Form(...),
    file: UploadFile = File(...)
):
    user = get_user(password)

    if not user:
        return PlainTextResponse("Invalid Password")

    try:
        filename = secrets.token_hex(8) + "_" + file.filename
        path = os.path.join(UPLOAD_DIR, filename)

        with open(path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)

        conn = db()
        conn.execute("""
        INSERT INTO files(user_id,file_name,saved_name,created_at)
        VALUES(?,?,?,?)
        """, (
            user["id"],
            file.filename,
            filename,
            datetime.utcnow().isoformat()
        ))
        conn.commit()
        conn.close()

    except Exception as e:
        return PlainTextResponse(str(e))

    return RedirectResponse(
        url=f"/dashboard?password={password}",
        status_code=303
    )


# -------------------------------
# DOWNLOAD
# -------------------------------
@app.get("/download/{file_id}")
def download(file_id: int, password: str):
    user = get_user(password)

    if not user:
        return PlainTextResponse("Invalid Password")

    conn = db()
    row = conn.execute(
        "SELECT * FROM files WHERE id=? AND user_id=?",
        (file_id, user["id"])
    ).fetchone()
    conn.close()

    if not row:
        return PlainTextResponse("File Not Found")

    path = os.path.join(UPLOAD_DIR, row["saved_name"])

    if not os.path.exists(path):
        return PlainTextResponse("Temporary file expired on Vercel")

    return FileResponse(path, filename=row["file_name"])


# -------------------------------
# DELETE FILE
# -------------------------------
@app.get("/delete-file/{file_id}")
def delete_file(file_id: int, password: str):
    user = get_user(password)

    if not user:
        return PlainTextResponse("Invalid Password")

    conn = db()

    row = conn.execute(
        "SELECT * FROM files WHERE id=? AND user_id=?",
        (file_id, user["id"])
    ).fetchone()

    if row:
        path = os.path.join(UPLOAD_DIR, row["saved_name"])
        if os.path.exists(path):
            os.remove(path)

        conn.execute(
            "DELETE FROM files WHERE id=?",
            (file_id,)
        )
        conn.commit()

    conn.close()

    return RedirectResponse(
        url=f"/dashboard?password={password}",
        status_code=303
    )


# -------------------------------
# ADD LINK
# -------------------------------
@app.post("/add-link")
def add_link(
    password: str = Form(...),
    url: str = Form(...)
):
    user = get_user(password)

    if not user:
        return PlainTextResponse("Invalid Password")

    conn = db()
    conn.execute(
        """
        INSERT INTO links(user_id,url,created_at)
        VALUES(?,?,?)
        """,
        (
            user["id"],
            url.strip(),
            datetime.utcnow().isoformat()
        )
    )
    conn.commit()
    conn.close()

    return RedirectResponse(
        url=f"/dashboard?password={password}",
        status_code=303
    )


# -------------------------------
# DELETE LINK
# -------------------------------
@app.get("/delete-link/{link_id}")
def delete_link(link_id: int, password: str):
    user = get_user(password)

    if not user:
        return PlainTextResponse("Invalid Password")

    conn = db()
    conn.execute(
        "DELETE FROM links WHERE id=? AND user_id=?",
        (link_id, user["id"])
    )
    conn.commit()
    conn.close()

    return RedirectResponse(
        url=f"/dashboard?password={password}",
        status_code=303
    )
