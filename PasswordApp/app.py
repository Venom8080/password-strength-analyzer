from functools import wraps
import hashlib
import math
import os
import sqlite3
import secrets
import string

from flask import (
    Flask,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

app = Flask(__name__)
app.config.setdefault(
    "DATABASE", os.path.join(os.path.dirname(os.path.abspath(__file__)), "passwordapp.db")
)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-change-in-production")

SPECIAL_CHARS = string.punctuation

MIN_PASSWORD_LEN = 6
MAX_PASSWORD_LEN = 128
SUGGESTED_LEN_TARGET = 32


def _coerce_bool(value, default=True):
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return value != 0
    if isinstance(value, str):
        return value.strip().lower() in ("true", "1", "yes", "on")
    return default


def hash_sha256(plain: str) -> str:
    if plain is None:
        plain = ""
    if not isinstance(plain, str):
        plain = str(plain)
    return hashlib.sha256(plain.encode("utf-8", errors="replace")).hexdigest()


def get_db():
    conn = sqlite3.connect(app.config["DATABASE"])
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    try:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                user_number TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS passwords (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_number TEXT NOT NULL,
                original_password TEXT NOT NULL,
                suggested_password TEXT NOT NULL,
                UNIQUE(user_number, original_password)
            );
            """
        )
        conn.commit()
    finally:
        conn.close()


def login_required_page(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_number" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)

    return decorated


def api_require_session():
    if "user_number" not in session:
        return jsonify({"error": "Unauthorized"}), 401
    return None


# --- BACKEND LOGIC FOR CHECKING ---
def calculate_crack_time(pw, upper, lower, num, sym):
    pool_size = 0
    if lower:
        pool_size += 26
    if upper:
        pool_size += 26
    if num:
        pool_size += 10
    if sym:
        pool_size += 32
    if pool_size == 0:
        pool_size = 26

    guesses_per_sec = 1e10
    combinations = math.pow(pool_size, len(pw))
    seconds = combinations / guesses_per_sec / 2

    if seconds < 1:
        return "Instantly"
    if seconds < 60:
        return "Less than a minute"
    if seconds < 3600:
        return f"{math.floor(seconds/60)} minutes"
    if seconds < 86400:
        return f"{math.floor(seconds/3600)} hours"
    if seconds < 31536000:
        return f"{math.floor(seconds/86400)} days"
    if seconds < 31536000 * 100:
        return f"{math.floor(seconds/31536000)} years"
    if seconds < 31536000 * 1000:
        return "Centuries"
    return "Millions of years (Secure)"


def check_password(pw):
    if pw is None:
        pw = ""
    elif not isinstance(pw, str):
        pw = str(pw)
    if not pw:
        return {
            "score": 0,
            "status": "None",
            "crack_time": "",
            "criteria": {
                "length": False,
                "upper": False,
                "lower": False,
                "number": False,
                "special": False,
                "no_space": True,
            },
        }

    score = 0
    has_upper = any(c.isupper() for c in pw)
    has_lower = any(c.islower() for c in pw)
    has_number = any(c.isdigit() for c in pw)
    has_special = any(c in SPECIAL_CHARS for c in pw)
    no_spaces = " " not in pw
    has_length = len(pw) >= 8

    if has_length:
        score += 1
    if len(pw) >= 12:
        score += 1
    if has_upper:
        score += 2
    if has_lower:
        score += 2
    if has_number:
        score += 2
    if has_special:
        score += 2
    if not no_spaces:
        score -= 2

    score = max(0, score)

    if score <= 3:
        status = "Weak"
    elif score <= 6:
        status = "Medium"
    else:
        status = "Strong"

    crack_time = calculate_crack_time(pw, has_upper, has_lower, has_number, has_special)

    return {
        "score": score,
        "status": status,
        "criteria": {
            "length": has_length,
            "upper": has_upper,
            "lower": has_lower,
            "number": has_number,
            "special": has_special,
            "no_space": no_spaces,
        },
        "crack_time": crack_time,
    }


def generate_password(length, upper, numbers, symbols):
    chars = string.ascii_lowercase
    if upper:
        chars += string.ascii_uppercase
    if numbers:
        chars += string.digits
    if symbols:
        chars += SPECIAL_CHARS

    return "".join(secrets.choice(chars) for _ in range(length))


def suggest_improved_password(pw: str) -> str:
    if pw is None:
        pw = ""
    elif not isinstance(pw, str):
        pw = str(pw)

    salt = secrets.token_bytes(32)
    nonce = secrets.token_urlsafe(16)
    key_material = pw.encode("utf-8", errors="replace") + salt + nonce.encode()
    h = hashlib.sha256(key_material)
    digest = h.digest()
    digest_hex = h.hexdigest()

    core = "".join(c for c in pw if c.isprintable() and not c.isspace())
    if len(core) < 2:
        core = "Pw"

    pool = string.ascii_letters + string.digits + SPECIAL_CHARS
    rng = secrets.SystemRandom()

    fp = "".join(pool[b % len(pool)] for b in digest[:18])

    required = [
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.digits),
        secrets.choice(SPECIAL_CHARS),
    ]
    extra = "".join(secrets.choice(pool) for _ in range(8))

    blend = list(core[:28] + nonce + digest_hex[:12] + fp + extra + "".join(required))
    rng.shuffle(blend)
    candidate = "".join(blend)

    while len(candidate) < SUGGESTED_LEN_TARGET:
        candidate += secrets.choice(pool)
    candidate = candidate[: min(SUGGESTED_LEN_TARGET + 8, MAX_PASSWORD_LEN)]

    for _ in range(12):
        if check_password(candidate)["status"] == "Strong":
            return candidate
        candidate = candidate + secrets.choice(pool)
        candidate = candidate[:MAX_PASSWORD_LEN]

    return candidate


def get_stored_suggestion(user_number: str, original_plain: str):
    if original_plain is None:
        original_plain = ""
    elif not isinstance(original_plain, str):
        original_plain = str(original_plain)
    h = hash_sha256(original_plain)
    conn = get_db()
    try:
        row = conn.execute(
            "SELECT suggested_password FROM passwords WHERE user_number = ? AND original_password = ?",
            (user_number, h),
        ).fetchone()
        return row[0] if row else None
    finally:
        conn.close()


def get_suggestion_or_generate(user_number: str, original_plain: str):
    """Return (suggested_password, from_storage)."""
    stored = get_stored_suggestion(user_number, original_plain)
    if stored:
        return stored, True
    return suggest_improved_password(original_plain), False


def allocate_user_number(conn) -> str:
    row = conn.execute("SELECT COALESCE(MAX(id), 0) FROM users").fetchone()
    next_n = int(row[0]) + 1
    return f"USER{next_n}"


def generate_simple_login_password() -> str:
    """Readable pattern like pass@-087!23 (digits vary)."""
    mid = secrets.randbelow(1000)
    tail = secrets.randbelow(100)
    return f"pass@-{mid:03d}!{tail:02d}"


def create_user(name: str):
    conn = get_db()
    try:
        login_pw = generate_simple_login_password()
        pw_hash = hash_sha256(login_pw)
        for _ in range(100):
            user_number = allocate_user_number(conn)
            try:
                conn.execute(
                    "INSERT INTO users (name, user_number, password_hash) VALUES (?, ?, ?)",
                    (name, user_number, pw_hash),
                )
                conn.commit()
                return user_number, login_pw
            except sqlite3.IntegrityError:
                conn.rollback()
                continue
        raise RuntimeError("Could not allocate user_number")
    finally:
        conn.close()


def normalize_user_number(user_number: str) -> str:
    if not user_number:
        return ""
    return user_number.strip().upper()


def verify_login(user_number: str, password: str):
    conn = get_db()
    try:
        row = conn.execute(
            "SELECT name, password_hash FROM users WHERE user_number = ?",
            (normalize_user_number(user_number),),
        ).fetchone()
        if not row:
            return None
        if hash_sha256(password) != row["password_hash"]:
            return None
        return {"name": row["name"], "user_number": normalize_user_number(user_number)}
    finally:
        conn.close()


# --- FLASK ROUTES ---
@app.before_request
def _ensure_db():
    if app.config.get("_db_initialized"):
        return
    init_db()
    app.config["_db_initialized"] = True


@app.route("/")
def home():
    if "user_number" in session:
        return redirect(url_for("choice"))
    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or request.form.get("name") or "").strip()
    if not name:
        if request.accept_mimetypes.best == "application/json" or request.is_json:
            return jsonify({"error": "Name is required"}), 400
        return render_template("register.html", error="Name is required"), 400
    user_number, login_pw = create_user(name)
    if request.is_json or request.accept_mimetypes.best == "application/json":
        return jsonify({"user_number": user_number, "password": login_pw})
    return render_template(
        "register.html", success=True, user_number=user_number, password=login_pw, name=name
    )


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")
    data = request.get_json(silent=True) or {}
    user_number = (data.get("user_number") or request.form.get("user_number") or "").strip()
    password = data.get("password") or request.form.get("password") or ""
    user = verify_login(user_number, password)
    if not user:
        if request.is_json or request.accept_mimetypes.best == "application/json":
            return jsonify({"error": "Invalid user number or password"}), 401
        return render_template("login.html", error="Invalid credentials"), 401
    session["user_number"] = user["user_number"]
    session["name"] = user["name"]
    if request.is_json or request.accept_mimetypes.best == "application/json":
        return jsonify({"ok": True, "user_number": user["user_number"]})
    return redirect(url_for("choice"))


@app.route("/logout", methods=["GET", "POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/choice")
@login_required_page
def choice():
    return render_template(
        "choice.html",
        user_number=session["user_number"],
        name=session.get("name", ""),
    )


@app.route("/strong")
@login_required_page
def strong():
    return render_template(
        "strong.html",
        user_number=session["user_number"],
        name=session.get("name", ""),
    )


@app.route("/recover")
@login_required_page
def recover():
    return render_template(
        "recover.html",
        user_number=session["user_number"],
        name=session.get("name", ""),
    )


@app.route("/dashboard")
@login_required_page
def dashboard():
    return redirect(url_for("choice"))


@app.route("/api/check", methods=["POST"])
def api_check():
    try:
        data = request.get_json(silent=True)
        if data is None:
            data = {}
        raw = data.get("password")
        result = check_password(raw)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/suggest", methods=["POST"])
def api_suggest():
    err = api_require_session()
    if err:
        return err
    try:
        data = request.get_json(silent=True)
        if data is None:
            data = {}
        raw = data.get("password")
        if raw is None:
            raw = ""
        elif not isinstance(raw, str):
            raw = str(raw)
        if not raw.strip():
            return jsonify({"error": "Empty password"}), 400
        user_number = session["user_number"]
        suggested, from_storage = get_suggestion_or_generate(user_number, raw)
        return jsonify(
            {
                "suggested_password": suggested,
                "from_storage": from_storage,
                "check": check_password(suggested),
            }
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/save", methods=["POST"])
def api_save():
    err = api_require_session()
    if err:
        return err
    try:
        data = request.get_json(silent=True)
        if data is None:
            data = {}
        original = data.get("original_password")
        suggested = data.get("suggested_password")
        if original is None or suggested is None:
            return jsonify({"error": "original_password and suggested_password required"}), 400
        if not isinstance(original, str):
            original = str(original)
        if not isinstance(suggested, str):
            suggested = str(suggested)
        if not original.strip():
            return jsonify({"error": "Empty password"}), 400
        if not suggested.strip():
            return jsonify({"error": "Empty password"}), 400
        user_number = session["user_number"]
        orig_hash = hash_sha256(original)
        conn = get_db()
        try:
            conn.execute(
                """
                INSERT INTO passwords (user_number, original_password, suggested_password)
                VALUES (?, ?, ?)
                ON CONFLICT(user_number, original_password) DO UPDATE SET
                    suggested_password = excluded.suggested_password
                """,
                (user_number, orig_hash, suggested),
            )
            conn.commit()
        finally:
            conn.close()
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/decrypt", methods=["POST"])
def api_decrypt():
    err = api_require_session()
    if err:
        return err
    try:
        data = request.get_json(silent=True)
        if data is None:
            data = {}
        original = data.get("original_password")
        if original is None:
            original = ""
        elif not isinstance(original, str):
            original = str(original)
        if not original.strip():
            return jsonify({"error": "Empty password"}), 400
        user_number = session["user_number"]
        h = hash_sha256(original)
        conn = get_db()
        try:
            row = conn.execute(
                "SELECT suggested_password FROM passwords WHERE user_number = ? AND original_password = ?",
                (user_number, h),
            ).fetchone()
        finally:
            conn.close()
        if not row:
            return jsonify({"error": "No saved suggestion for this password"}), 404
        return jsonify({"suggested_password": row[0]})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/generate", methods=["POST"])
def api_generate():
    try:
        data = request.get_json(silent=True)
        if data is None:
            data = {}
        length = int(data.get("length", 16))
        length = max(MIN_PASSWORD_LEN, min(MAX_PASSWORD_LEN, length))
        upper = _coerce_bool(data.get("upper"), True)
        numbers = _coerce_bool(data.get("numbers"), True)
        symbols = _coerce_bool(data.get("symbols"), True)

        pw = generate_password(length, upper, numbers, symbols)
        result = check_password(pw)
        result["password"] = pw
        return jsonify(result)
    except (TypeError, ValueError, OverflowError) as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    init_db()
    app.run(debug=True)
