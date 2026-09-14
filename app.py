import sqlite3
import logging
from fastapi import FastAPI, Form
from fastapi.responses import HTMLResponse, RedirectResponse
import uvicorn

db_name = "iaw301"


connection = sqlite3.connect(database=db_name)
cursor = connection.cursor()
cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL
    )
""")
cursor.executemany("""
    INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)
""", [
    ("admin", "123"),
    ("user1", "456"),
    ("user2", "password3")
])
connection.commit()
cursor.close()
connection.close()

app = FastAPI(title="iaw301_webapp")
current_user = None

@app.get("/")
def get_login_form():
    if current_user:
        return RedirectResponse(url="/dashboard")

    return HTMLResponse(content="""
    <html>
        <head><title>Login</title></head>
        <meta charset="UTF-8">
        <body>
            <h1>Login</h1>
            <form action="/login" method="post">
                <label for="username">Username/Email:</label>
                <input type="text" id="username" name="username" required><br><br>
                <label for="password">Password:</label>
                <input type="password" id="password" name="password" required><br><br>
                <input type="submit" value="Login">
            </form>
        </body>
    </html>
    """)

@app.post("/login")
def login(username: str = Form(...), password: str = Form(...)):
    global current_user

    connection = sqlite3.connect(database=db_name)
    cursor = connection.cursor()
    cursor.execute(
        "SELECT id FROM users WHERE username = ? AND password = ?",
        (username, password)
    )
    result = cursor.fetchone()
    cursor.close()
    connection.close()

    if result:
        logging.info(f"LOGIN SUCCESS - username='{username}'")
        current_user = username
        return RedirectResponse(url="/dashboard", status_code=302)
    else:
        logging.warning(f"LOGIN FAILED - username='{username}'")
        return HTMLResponse(content="<h1>Sai username hoặc password</h1>", status_code=401)

@app.get("/dashboard")
def dashboard():
    if not current_user:
        return RedirectResponse(url="/")

    return HTMLResponse(content=f"""
    <html>
        <head><title>Dashboard</title></head>
        <meta charset="UTF-8">
        <body>
            <h1>Xin chào, {current_user}!</h1>
            <p>Bạn đã đăng nhập thành công.</p>
            <a href="/logout">logout</a>
        </body>
    </html>
    """)


@app.get("/logout")
def logout():
    global current_user
    logging.info(f"LOGOUT - username='{current_user}'")
    current_user = None
    return RedirectResponse(url="/")

@app.get("/ping")
def ping():
    return "pong"

@app.get("/all", response_class=HTMLResponse)
def get_all_users():
    connection = sqlite3.connect(database=db_name)
    cursor = connection.cursor()
    cursor.execute("SELECT id, username, password FROM users")
    users = cursor.fetchall()
    cursor.close()
    connection.close()

    rows_html = "".join(
        f"<tr><td>{u[0]}</td><td>{u[1]}</td><td>{u[2]}</td></tr>"
        for u in users
    )

    return HTMLResponse(content=f"""
    <html>
        <head><title>All Users</title></head>
        <meta charset="UTF-8">
        <body>
            <h1>Danh sách Users</h1>
            <table border="1" cellpadding="8" cellspacing="0">
                <tr>
                    <th>ID</th>
                    <th>Username</th>
                    <th>Password</th>
                </tr>
                {rows_html}
            </table>
            <br>
            <a href="/">Back</a>
        </body>
    </html>
    """)



if __name__ == "__main__":
    uvicorn.run(app=app, host="127.0.0.1", port=8888)