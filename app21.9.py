import hashlib
import hmac
import html
import os
import secrets
import sqlite3
import threading
import time
from collections import deque
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone

import jwt                     
import uvicorn
from fastapi import Cookie, Depends, FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer


db_name = os.environ.get("DB_NAME", "iaw301")



JWT_SECRET = os.environ.get("JWT_SECRET") or secrets.token_urlsafe(32)
JWT_ALGORITHM = "HS256"
JWT_EXPIRE_MINUTES = 15


COOKIE_NAME = "session_id"
SESSION_IDLE_TIMEOUT = 30 * 60                                            
SESSION_ABSOLUTE_TIMEOUT = 8 * 3600                                     

COOKIE_SECURE = os.environ.get("COOKIE_SECURE", "0") == "1"


ATTEMPT_WINDOW = 15 * 60                                            
MAX_FAILS_PER_USER = 5                                               
MAX_FAILS_PER_IP = 20                                                      

                                                                              
                                                                             
LOCKOUT_BASE_SECONDS = 60
LOCKOUT_MAX_SECONDS = 60 * 60
                                                                             
STRIKE_MEMORY = 24 * 3600

                                                                                 
                                                                 
RATE_LIMIT_GLOBAL = (100, 60)                                             
RATE_LIMIT_LOGIN = (10, 60)                                                    
LOGIN_PATHS = {"/login", "/api/jwt/login"}

                                                 
HASH_PREFIX = "pbkdf2_sha256"
HASH_ITERATIONS = 200_000



def hash_password(password: str) -> str:
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, HASH_ITERATIONS)
    return f"{HASH_PREFIX}${HASH_ITERATIONS}${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        prefix, iterations, salt_hex, hash_hex = stored.split("$")
        if prefix != HASH_PREFIX:
            return False
        dk = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), bytes.fromhex(salt_hex), int(iterations)
        )
        return hmac.compare_digest(dk.hex(), hash_hex)                         
    except (ValueError, TypeError):
        return False



DUMMY_HASH = hash_password("dummy-password")



@contextmanager
def db():
    connection = sqlite3.connect(database=db_name)
    try:
        yield connection
        connection.commit()
    finally:
        connection.close()


def init_db():
    with db() as conn:
        cur = conn.cursor()

        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL
            )
        """)

                                                  
        columns = [r[1] for r in cur.execute("PRAGMA table_info(users)")]
        if "role" not in columns:
            cur.execute("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'user'")

                                           
        for username, password in [("admin", "123"), ("user1", "456"), ("user2", "password3")]:
            cur.execute(
                "INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)",
                (username, hash_password(password)),
            )
        cur.execute("UPDATE users SET role = 'admin' WHERE username = 'admin'")

                                                
        for user_id, pw in cur.execute("SELECT id, password FROM users").fetchall():
            if not pw.startswith(HASH_PREFIX + "$"):
                cur.execute(
                    "UPDATE users SET password = ? WHERE id = ?",
                    (hash_password(pw), user_id),
                )

                                                               
        cur.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                id_hash TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                created_at REAL NOT NULL,
                last_seen REAL NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)

                                            
        cur.execute("""
            CREATE TABLE IF NOT EXISTS revoked_tokens (
                jti TEXT PRIMARY KEY,
                exp REAL NOT NULL
            )
        """)

                                                           
        cur.execute("""
            CREATE TABLE IF NOT EXISTS login_failures (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL,
                username TEXT NOT NULL,
                ts REAL NOT NULL
            )
        """)
        cur.execute("CREATE INDEX IF NOT EXISTS idx_fail_user ON login_failures(username, ts)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_fail_ip ON login_failures(ip, ts)")

                                                                                  
        cur.execute("""
            CREATE TABLE IF NOT EXISTS login_lockouts (
                key TEXT PRIMARY KEY,
                strikes INTEGER NOT NULL,       -- số lần bị khoá liên tiếp
                locked_until REAL NOT NULL,     -- thời điểm được mở khoá
                last_strike_ts REAL NOT NULL    -- lần khoá gần nhất
            )
        """)


init_db()

app = FastAPI(title="iaw301_webapp")



class SlidingWindowRateLimiter:
    """
    Lưu thời điểm các request gần đây của mỗi key; nếu số request trong cửa sổ
    vượt giới hạn thì từ chối. Lưu trong RAM: mất khi restart và không chia sẻ
    giữa nhiều process -> production nên dùng Redis (hoặc rate limit ở Nginx).
    """

    def __init__(self):
        self._hits: dict[tuple, deque] = {}
        self._lock = threading.Lock()
        self._calls = 0

    def check(self, key: tuple, limit: int, window: int):
        """Trả về (được_phép, số_giây_phải_chờ, số_request_còn_lại)."""
        now = time.time()
        with self._lock:
            self._calls += 1
            if self._calls % 1000 == 0:
                self._cleanup(now)

            hits = self._hits.setdefault(key, deque())
            while hits and hits[0] <= now - window:
                hits.popleft()

            if len(hits) >= limit:
                                                                                  
                return False, int(hits[0] + window - now) + 1, 0

            hits.append(now)
            return True, 0, limit - len(hits)

    def _cleanup(self, now: float):
        """Xoá key không còn hoạt động để RAM không phình ra."""
        max_window = max(RATE_LIMIT_GLOBAL[1], RATE_LIMIT_LOGIN[1])
        for key in [k for k, q in self._hits.items() if not q or q[-1] <= now - max_window]:
            del self._hits[key]


limiter = SlidingWindowRateLimiter()


def rate_limited_response(request: Request, retry_after: int, limit: int):
    headers = {"Retry-After": str(retry_after), "X-RateLimit-Limit": str(limit),
               "X-RateLimit-Remaining": "0"}
    if request.url.path.startswith("/api/"):
        return JSONResponse(
            status_code=429,
            content={"detail": f"Qua nhieu request, thu lai sau {retry_after} giay"},
            headers=headers,
        )
    resp = page(
        "Too Many Requests",
        f"<h1>Qua nhieu request</h1><p>Vui long thu lai sau {retry_after} giay.</p>",
        status_code=429,
    )
    resp.headers.update(headers)
    return resp


@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    ip = client_ip(request)

    checks = [("global", RATE_LIMIT_GLOBAL)]
    if request.method == "POST" and request.url.path in LOGIN_PATHS:
        checks.append(("login", RATE_LIMIT_LOGIN))                      

    tightest = None                                               
    for name, (limit, window) in checks:
        allowed, retry_after, remaining = limiter.check((name, ip), limit, window)
        if not allowed:
            return rate_limited_response(request, retry_after, limit)
        if tightest is None or remaining < tightest[0]:
            tightest = (remaining, limit)

    response = await call_next(request)
    response.headers["X-RateLimit-Limit"] = str(tightest[1])
    response.headers["X-RateLimit-Remaining"] = str(tightest[0])
    return response


                                                                       
                   
                                                                       
class TooManyAttempts(Exception):
    def __init__(self, retry_after: int):
        self.retry_after = retry_after


def lockout_duration(strikes: int) -> int:
    """Exponential backoff: BASE * 2^(strikes-1), giới hạn bởi MAX."""
    exponent = min(max(strikes, 1) - 1, 30)                      
    return min(LOCKOUT_BASE_SECONDS * 2 ** exponent, LOCKOUT_MAX_SECONDS)


def format_wait(seconds: int) -> str:
    minutes, secs = divmod(seconds, 60)
    if minutes and secs:
        return f"{minutes} phut {secs} giay"
    return f"{minutes} phut" if minutes else f"{secs} giay"


def _lock_key(kind: str, value: str) -> str:
    return f"{kind}:{value}"


def _seconds_locked(cur, key: str) -> int:
    """Số giây còn bị khoá của key (0 nếu không bị khoá)."""
    row = cur.execute(
        "SELECT locked_until FROM login_lockouts WHERE key = ?", (key,)
    ).fetchone()
    now = time.time()
    if row and row[0] > now:
        return int(row[0] - now) + 1
    return 0


def _register_failure(cur, kind: str, column: str, value: str, limit: int):
    """
    Sau mỗi lần sai: nếu số lần sai (kể từ lần khoá trước) đạt ngưỡng
    thì khoá key này, thời gian khoá tăng theo số lần vi phạm liên tiếp.
    """
    now = time.time()
    key = _lock_key(kind, value)
    row = cur.execute(
        "SELECT strikes, last_strike_ts FROM login_lockouts WHERE key = ?", (key,)
    ).fetchone()
    strikes, last_strike = row if row else (0, 0.0)

    if strikes and now - last_strike > STRIKE_MEMORY:
        strikes, last_strike = 0, 0.0                              

                                                                                   
    since = max(now - ATTEMPT_WINDOW, last_strike)
    (count,) = cur.execute(
        f"SELECT COUNT(*) FROM login_failures WHERE {column} = ? AND ts > ?",
        (value, since),
    ).fetchone()

    if count >= limit:
        strikes += 1
        cur.execute(
            """
            INSERT INTO login_lockouts (key, strikes, locked_until, last_strike_ts)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(key) DO UPDATE SET
                strikes = excluded.strikes,
                locked_until = excluded.locked_until,
                last_strike_ts = excluded.last_strike_ts
            """,
            (key, strikes, now + lockout_duration(strikes), now),
        )


def authenticate(ip: str, username: str, password: str):
    """
    Xác thực username/password, có giới hạn số lần thử và khoá luỹ tiến.
    - Trả về dict user nếu đúng
    - Trả về None nếu sai
    - Raise TooManyAttempts nếu đang bị khoá
    """
    uname = username[:64]                                                     
    with db() as conn:
        cur = conn.cursor()

                                                       
        wait = max(
            _seconds_locked(cur, _lock_key("user", uname)),
            _seconds_locked(cur, _lock_key("ip", ip)),
        )
        if wait:
            raise TooManyAttempts(wait)

                                                                            
        row = cur.execute(
            "SELECT id, username, password, role FROM users WHERE username = ?",
            (username,),
        ).fetchone()
        stored_hash = row[2] if row else DUMMY_HASH
        password_ok = verify_password(password, stored_hash)

        if row and password_ok:
                                                                     
            cur.execute("DELETE FROM login_failures WHERE username = ?", (uname,))
            cur.execute("DELETE FROM login_lockouts WHERE key = ?", (_lock_key("user", uname),))
            return {"id": row[0], "username": row[1], "role": row[3]}

                                                      
        now = time.time()
        cur.execute(
            "INSERT INTO login_failures (ip, username, ts) VALUES (?, ?, ?)",
            (ip, uname, now),
        )
        _register_failure(cur, "user", "username", uname, MAX_FAILS_PER_USER)
        _register_failure(cur, "ip", "ip", ip, MAX_FAILS_PER_IP)

                           
        cur.execute("DELETE FROM login_failures WHERE ts < ?", (now - ATTEMPT_WINDOW,))
        cur.execute(
            "DELETE FROM login_lockouts WHERE locked_until < ? AND last_strike_ts < ?",
            (now, now - STRIKE_MEMORY),
        )
        return None


def client_ip(request: Request) -> str:
                                                                                     
    return request.client.host if request.client else "unknown"


                                                                       
                                 
                                                                       
def _hash_session_id(session_id: str) -> str:
    return hashlib.sha256(session_id.encode()).hexdigest()


def create_session(user_id: int) -> str:
    """Tạo session mới (session id ngẫu nhiên, không đoán được)."""
    session_id = secrets.token_urlsafe(32)
    now = time.time()
    with db() as conn:
                             
        conn.execute(
            "DELETE FROM sessions WHERE last_seen < ? OR created_at < ?",
            (now - SESSION_IDLE_TIMEOUT, now - SESSION_ABSOLUTE_TIMEOUT),
        )
        conn.execute(
            "INSERT INTO sessions (id_hash, user_id, created_at, last_seen) VALUES (?, ?, ?, ?)",
            (_hash_session_id(session_id), user_id, now, now),
        )
    return session_id


def destroy_session(session_id: str):
    with db() as conn:
        conn.execute("DELETE FROM sessions WHERE id_hash = ?", (_hash_session_id(session_id),))


def redirect_to_login():
    return HTTPException(status_code=303, headers={"Location": "/login-form"})


def get_session_user(session_id: str = Cookie(default=None, alias=COOKIE_NAME)):
    """Dependency: lấy user từ session cookie, không hợp lệ -> chuyển về trang login."""
    if not session_id:
        raise redirect_to_login()

    now = time.time()
    with db() as conn:
        row = conn.execute(
            """
            SELECT u.id, u.username, u.role, s.created_at, s.last_seen
            FROM sessions s JOIN users u ON u.id = s.user_id
            WHERE s.id_hash = ?
            """,
            (_hash_session_id(session_id),),
        ).fetchone()

        if not row:
            raise redirect_to_login()

        _, _, _, created_at, last_seen = row
        if now - last_seen > SESSION_IDLE_TIMEOUT or now - created_at > SESSION_ABSOLUTE_TIMEOUT:
            conn.execute("DELETE FROM sessions WHERE id_hash = ?", (_hash_session_id(session_id),))
            conn.commit()
            raise redirect_to_login()

                            
        conn.execute(
            "UPDATE sessions SET last_seen = ? WHERE id_hash = ?",
            (now, _hash_session_id(session_id)),
        )
    return {"id": row[0], "username": row[1], "role": row[2]}


def require_admin_session(user=Depends(get_session_user)):
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Chi admin moi duoc truy cap")
    return user


                                                                       
                    
                                                                       
bearer_scheme = HTTPBearer(auto_error=False)


def create_access_token(user: dict) -> tuple[str, int]:
    now = datetime.now(timezone.utc)
    expire = now + timedelta(minutes=JWT_EXPIRE_MINUTES)
    payload = {
        "sub": str(user["id"]),                                     
        "username": user["username"],
        "role": user["role"],
        "iat": now,
        "exp": expire,
        "jti": secrets.token_hex(16),                                            
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return token, JWT_EXPIRE_MINUTES * 60


def get_jwt_payload(credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme)):
    """Dependency: đọc header 'Authorization: Bearer <token>' và verify."""
    unauthorized = {"WWW-Authenticate": "Bearer"}
    if credentials is None:
        raise HTTPException(401, "Thieu token", headers=unauthorized)

    try:
        payload = jwt.decode(
            credentials.credentials,
            JWT_SECRET,
            algorithms=[JWT_ALGORITHM],                                                 
            options={"require": ["exp", "iat", "sub", "jti"]},
        )
    except jwt.ExpiredSignatureError:
        raise HTTPException(401, "Token het han", headers=unauthorized)
    except jwt.InvalidTokenError:
        raise HTTPException(401, "Token khong hop le", headers=unauthorized)

    with db() as conn:
        revoked = conn.execute(
            "SELECT 1 FROM revoked_tokens WHERE jti = ?", (payload["jti"],)
        ).fetchone()
        conn.execute("DELETE FROM revoked_tokens WHERE exp < ?", (time.time(),))
    if revoked:
        raise HTTPException(401, "Token da bi thu hoi", headers=unauthorized)

    return payload


                                                                       
             
                                                                       
def page(title: str, body: str, status_code: int = 200) -> HTMLResponse:
    return HTMLResponse(
        status_code=status_code,
        content=f"""<!DOCTYPE html>
<html>
    <head>
        <meta charset="UTF-8">
        <title>{html.escape(title)}</title>
    </head>
    <body>
        {body}
    </body>
</html>""",
    )


LOGOUT_FORM = '<form action="/logout" method="post"><input type="submit" value="Logout"></form>'


                                                                       
        
                                                                       
@app.get("/ping")
def ping():
    return "pong"


                                                                 
@app.get("/all", response_class=HTMLResponse)
def get_all_users(user=Depends(require_admin_session)):
    with db() as conn:
        rows = conn.execute("SELECT id, username, role FROM users").fetchall()

    rows_html = "".join(
        f"<tr><td>{r[0]}</td><td>{html.escape(r[1])}</td><td>{html.escape(r[2])}</td></tr>"
        for r in rows
    )
    return page("All Users", f"""
        <h1>Users</h1>
        <table border="1" cellpadding="5" cellspacing="0">
            <tr><th>id</th><th>username</th><th>role</th></tr>
            {rows_html}
        </table>
        <p><a href="/profile">Ve profile</a></p>
    """)


                                         
@app.get("/", response_class=HTMLResponse)
@app.get("/login-form", response_class=HTMLResponse)
def get_login_form():
    return page("Login", """
        <h1>Login</h1>
        <form action="/login" method="post">
            <label for="username">Username/Email:</label>
            <input type="text" id="username" name="username" required><br><br>
            <label for="password">Password:</label>
            <input type="password" id="password" name="password" required><br><br>
            <input type="submit" value="Login">
        </form>
    """)


                                                  
@app.post("/login", response_class=HTMLResponse)
def login(request: Request, username: str = Form(...), password: str = Form(...)):
    try:
        user = authenticate(client_ip(request), username, password)
    except TooManyAttempts as e:
        resp = page(
            "Login",
            f"""<h1>Qua nhieu lan thu</h1>
                <p>Tai khoan/dia chi IP bi khoa tam thoi. Vui long thu lai sau {format_wait(e.retry_after)}.</p>
                <a href="/login-form">Quay lai</a>""",
            status_code=429,
        )
        resp.headers["Retry-After"] = str(e.retry_after)
        return resp

    if not user:
                                                                      
        return page(
            "Login",
            """<h1>Login that bai</h1>
               <p>Sai username hoac password.</p>
               <a href="/login-form">Quay lai</a>""",
            status_code=401,
        )

                                                                    
    session_id = create_session(user["id"])
    resp = page(
        "Login",
        f"""<h1>Login thanh cong</h1>
            <p>Xin chao, {html.escape(user['username'])}!</p>
            <p><a href="/profile">Xem profile</a></p>
            {LOGOUT_FORM}""",
    )
    resp.set_cookie(
        key=COOKIE_NAME,
        value=session_id,
        httponly=True,                                                              
        secure=COOKIE_SECURE,                                   
        samesite="lax",                                 
        max_age=SESSION_ABSOLUTE_TIMEOUT,
        path="/",
    )
    return resp


@app.get("/profile", response_class=HTMLResponse)
def profile(user=Depends(get_session_user)):
    admin_link = '<p><a href="/all">Danh sach user</a></p>' if user["role"] == "admin" else ""
    return page("Profile", f"""
        <h1>Profile</h1>
        <p>Username: {html.escape(user['username'])}</p>
        <p>Role: {html.escape(user['role'])}</p>
        {admin_link}
        {LOGOUT_FORM}
    """)



@app.post("/logout", response_class=HTMLResponse)
def logout(session_id: str = Cookie(default=None, alias=COOKIE_NAME)):
    if session_id:
        destroy_session(session_id)                           
    resp = page("Logout", """
        <h1>Da dang xuat</h1>
        <a href="/login-form">Dang nhap lai</a>
    """)
    resp.delete_cookie(key=COOKIE_NAME, path="/")
    return resp


                                                                       
         
                                                                       
@app.post("/api/jwt/login")
def jwt_login(request: Request, username: str = Form(...), password: str = Form(...)):
    try:
        user = authenticate(client_ip(request), username, password)
    except TooManyAttempts as e:
        return JSONResponse(
            status_code=429,
            content={"detail": f"Qua nhieu lan thu, thu lai sau {format_wait(e.retry_after)}"},
            headers={"Retry-After": str(e.retry_after)},
        )

    if not user:
        raise HTTPException(status_code=401, detail="Sai username hoac password")

    token, expires_in = create_access_token(user)
    return {"access_token": token, "token_type": "bearer", "expires_in": expires_in}


@app.get("/api/jwt/me")
def jwt_me(payload=Depends(get_jwt_payload)):
    return {"id": int(payload["sub"]), "username": payload["username"], "role": payload["role"]}


@app.get("/api/jwt/admin")
def jwt_admin(payload=Depends(get_jwt_payload)):
    if payload["role"] != "admin":
        raise HTTPException(status_code=403, detail="Chi admin moi duoc truy cap")
    with db() as conn:
        rows = conn.execute("SELECT id, username, role FROM users").fetchall()
    return [{"id": r[0], "username": r[1], "role": r[2]} for r in rows]


@app.post("/api/jwt/logout")
def jwt_logout(payload=Depends(get_jwt_payload)):
                                                                                         
    with db() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO revoked_tokens (jti, exp) VALUES (?, ?)",
            (payload["jti"], payload["exp"]),
        )
    return {"detail": "Da thu hoi token"}


if __name__ == "__main__":
    uvicorn.run(app=app, host="127.0.0.1", port=8888)