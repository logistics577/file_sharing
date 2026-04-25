# main.py
# pip install fastapi uvicorn python-multipart
# uvicorn main:app --reload

import os
import sqlite3
import shutil
import secrets
from datetime import datetime
from urllib.parse import quote

from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, FileResponse

app = FastAPI(title="Private Vault")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
DB_FILE = os.path.join(BASE_DIR, "vault.db")

os.makedirs(UPLOAD_DIR, exist_ok=True)


# ---------------- DB ---------------- #

def db():
    conn = sqlite3.connect(DB_FILE)
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


init_db()


# ---------------- HELPERS ---------------- #

def get_user(password):
    conn = db()
    row = conn.execute(
        "SELECT * FROM users WHERE password=?",
        (password,)
    ).fetchone()
    conn.close()
    return row


def create_password():
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


# ---------------- HOME ---------------- #

@app.get("/", response_class=HTMLResponse)
def home():
    return """
    <html>
    <head>
    <style>
    body{font-family:Arial;background:#f2f2f2;padding:40px}
    .box{max-width:500px;margin:auto;background:white;padding:25px;border-radius:10px}
    input,button{width:100%;padding:12px;margin-top:10px}
    button{background:#111;color:white;border:none}
    </style>
    </head>
    <body>
      <div class='box'>
        <h2>Private Vault</h2>

        <form method='post' action='/create-password'>
          <button>Create 6 Digit Password</button>
        </form>

        <hr>

        <form method='post' action='/login'>
          <input name='password' placeholder='Enter Password' required>
          <button>Open Vault</button>
        </form>
      </div>
    </body>
    </html>
    """


# ---------------- CREATE PASSWORD ---------------- #

@app.post("/create-password", response_class=HTMLResponse)
def create_pass():
    pwd = create_password()
    return f"""
    <html>
    <body style="font-family:Arial;padding:40px">
      <h2>Your Password</h2>
      <h1>{pwd}</h1>
      <a href="/dashboard?password={pwd}">Open Dashboard</a>
    </body>
    </html>
    """


# ---------------- LOGIN ---------------- #

@app.post("/login")
def login(password: str = Form(...)):
    if not get_user(password):
        raise HTTPException(status_code=401, detail="Wrong Password")
    return RedirectResponse(
        url=f"/dashboard?password={password}",
        status_code=303
    )


# ---------------- DASHBOARD ---------------- #

@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(password: str):
    user = get_user(password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid Password")

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
              <button>Download</button>
            </a>
          </td>
          <td>
            <a href="/delete-file/{f['id']}?password={password}">
              <button style='background:red'>Delete</button>
            </a>
          </td>
        </tr>
        """

    link_html = ""
    for l in links:
        safe_url = l["url"]
        link_html += f"""
        <tr>
          <td>
            <a href="{safe_url}" target="_blank">{safe_url}</a>
          </td>
          <td>
            <a href="/delete-link/{l['id']}?password={password}">
              <button style='background:red'>Delete</button>
            </a>
          </td>
        </tr>
        """

    return f"""
    <html>
    <head>
    <style>
    body{{font-family:Arial;background:#f2f2f2;padding:30px}}
    .box{{background:white;padding:25px;border-radius:10px}}
    input,button{{padding:10px;width:100%;margin-top:10px}}
    textarea{{width:100%;padding:10px}}
    button{{background:#111;color:white;border:none}}
    table{{width:100%;border-collapse:collapse;margin-top:20px}}
    td,th{{border:1px solid #ccc;padding:10px}}
    </style>
    </head>
    <body>
      <div class='box'>
        <h2>Dashboard</h2>
        <p><b>Password:</b> {password}</p>

        <h3>Upload File</h3>
        <form method="post" enctype="multipart/form-data" action="/upload">
          <input type="hidden" name="password" value="{password}">
          <input type="file" name="file" required>
          <button>Upload</button>
        </form>

        <h3>Save URL Link</h3>
        <form method="post" action="/add-link">
          <input type="hidden" name="password" value="{password}">
          <input type="text" name="url" placeholder="Paste any URL" required>
          <button>Save Link</button>
        </form>

        <h3>Files</h3>
        <table>
          <tr>
            <th>Name</th>
            <th>Download</th>
            <th>Delete</th>
          </tr>
          {file_html}
        </table>

        <h3>Saved Links (Copy / Open only)</h3>
        <table>
          <tr>
            <th>URL</th>
            <th>Delete</th>
          </tr>
          {link_html}
        </table>

      </div>
    </body>
    </html>
    """


# ---------------- UPLOAD FILE ---------------- #

@app.post("/upload")
def upload(
    password: str = Form(...),
    file: UploadFile = File(...)
):
    user = get_user(password)
    if not user:
        raise HTTPException(status_code=401)

    saved = secrets.token_hex(10) + "_" + file.filename
    path = os.path.join(UPLOAD_DIR, saved)

    with open(path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    conn = db()
    conn.execute(
        """
        INSERT INTO files(user_id,file_name,saved_name,created_at)
        VALUES(?,?,?,?)
        """,
        (
            user["id"],
            file.filename,
            saved,
            datetime.now().isoformat()
        )
    )
    conn.commit()
    conn.close()

    return RedirectResponse(
        url=f"/dashboard?password={password}",
        status_code=303
    )


# ---------------- DOWNLOAD ---------------- #

@app.get("/download/{file_id}")
def download(file_id: int, password: str):
    user = get_user(password)
    if not user:
        raise HTTPException(status_code=401)

    conn = db()
    row = conn.execute(
        "SELECT * FROM files WHERE id=? AND user_id=?",
        (file_id, user["id"])
    ).fetchone()
    conn.close()

    if not row:
        raise HTTPException(status_code=404)

    path = os.path.join(UPLOAD_DIR, row["saved_name"])

    return FileResponse(
        path,
        filename=row["file_name"]
    )


# ---------------- DELETE FILE ---------------- #

@app.get("/delete-file/{file_id}")
def delete_file(file_id: int, password: str):
    user = get_user(password)
    if not user:
        raise HTTPException(status_code=401)

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


# ---------------- ADD LINK ---------------- #

@app.post("/add-link")
def add_link(
    password: str = Form(...),
    url: str = Form(...)
):
    user = get_user(password)
    if not user:
        raise HTTPException(status_code=401)

    conn = db()
    conn.execute(
        """
        INSERT INTO links(user_id,url,created_at)
        VALUES(?,?,?)
        """,
        (
            user["id"],
            url.strip(),
            datetime.now().isoformat()
        )
    )
    conn.commit()
    conn.close()

    return RedirectResponse(
        url=f"/dashboard?password={password}",
        status_code=303
    )


# ---------------- DELETE LINK ---------------- #

@app.get("/delete-link/{link_id}")
def delete_link(link_id: int, password: str):
    user = get_user(password)
    if not user:
        raise HTTPException(status_code=401)

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
