import os, sqlite3, stripe
from functools import wraps
from flask import (Flask, render_template, request, redirect,
                   url_for, session, flash, g)
from werkzeug.security import generate_password_hash, check_password_hash
from authlib.integrations.flask_client import OAuth

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "غيّر-هذا-المفتاح")
DB = "souq.db"

# ---------- Google OAuth (اختياري) ----------
# ضع GOOGLE_CLIENT_ID و GOOGLE_CLIENT_SECRET من console.cloud.google.com
oauth = OAuth(app)
GOOGLE_ON = bool(os.environ.get("GOOGLE_CLIENT_ID"))
if GOOGLE_ON:
    oauth.register(
        name="google",
        client_id=os.environ["GOOGLE_CLIENT_ID"],
        client_secret=os.environ["GOOGLE_CLIENT_SECRET"],
        server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
        client_kwargs={"scope": "openid email profile"},
    )

# ---------- Stripe (اختياري) ----------
# ضع STRIPE_SECRET_KEY من dashboard.stripe.com
stripe.api_key = os.environ.get("STRIPE_SECRET_KEY")
STRIPE_ON = bool(stripe.api_key)
ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL", "").lower()  # بريد المدير

# ---------- العملة ----------
CURRENCY = "د.ل"  # غيّرها هنا فقط
LYD_PER_USD = float(os.environ.get("LYD_PER_USD", "5.0"))  # سعر الصرف لدفع البطاقة

@app.context_processor
def inject_currency():
    return {"currency": CURRENCY}

# ---------- المنتجات الافتراضية ----------
PRODUCTS = [
    {"id": 1, "name": "سماعات لاسلكية", "price": 120, "old": 180, "cat": "إلكترونيات", "emoji": "🎧"},
    {"id": 2, "name": "ساعة ذكية", "price": 250, "old": None, "cat": "إلكترونيات", "emoji": "⌚"},
    {"id": 3, "name": "حقيبة ظهر", "price": 75, "old": 110, "cat": "أزياء", "emoji": "🎒"},
    {"id": 4, "name": "حذاء رياضي", "price": 160, "old": None, "cat": "أزياء", "emoji": "👟"},
    {"id": 5, "name": "كوب حراري", "price": 30, "old": 45, "cat": "المنزل", "emoji": "☕"},
    {"id": 6, "name": "مصباح مكتب", "price": 55, "old": None, "cat": "المنزل", "emoji": "💡"},
]

# ---------- قاعدة البيانات ----------
def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(_):
    d = g.pop("db", None)
    if d: d.close()

def init_db():
    with sqlite3.connect(DB) as c:
        c.execute("""CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY, name TEXT, email TEXT UNIQUE, password TEXT,
            is_admin INTEGER DEFAULT 0)""")
        c.execute("""CREATE TABLE IF NOT EXISTS products(
            id INTEGER PRIMARY KEY, name TEXT, price REAL, old REAL, cat TEXT, emoji TEXT)""")
        c.execute("""CREATE TABLE IF NOT EXISTS orders(
            id INTEGER PRIMARY KEY, user TEXT, total REAL, method TEXT, status TEXT,
            items TEXT, created TEXT DEFAULT CURRENT_TIMESTAMP)""")
        if not c.execute("SELECT 1 FROM products").fetchone():
            c.executemany("INSERT INTO products(id,name,price,old,cat,emoji) VALUES(?,?,?,?,?,?)",
                [(p["id"], p["name"], p["price"], p["old"], p["cat"], p["emoji"]) for p in PRODUCTS])

def login_required(f):
    @wraps(f)
    def w(*a, **k):
        if "user" not in session:
            return redirect(url_for("login"))
        return f(*a, **k)
    return w

def admin_required(f):
    @wraps(f)
    @login_required
    def w(*a, **k):
        if not session.get("admin"):
            return redirect(url_for("shop"))
        return f(*a, **k)
    return w

def set_session(u):
    session["user"] = u["name"]
    # المدير: البريد المحدد في ADMIN_EMAIL، أو أول مستخدم مسجّل
    first = db().execute("SELECT MIN(id) m FROM users").fetchone()["m"]
    session["admin"] = bool(u["is_admin"]) or u["email"] == ADMIN_EMAIL or (not ADMIN_EMAIL and u["id"] == first)

def get_product(pid):
    return db().execute("SELECT * FROM products WHERE id=?", (pid,)).fetchone()

def cart_rows():
    return [(get_product(int(i)), q) for i, q in session.get("cart", {}).items() if get_product(int(i))]

# ---------- تسجيل الدخول ----------
@app.route("/", methods=["GET", "POST"])
@app.route("/login", methods=["GET", "POST"])
def login():
    if "user" in session:
        return redirect(url_for("shop"))
    if request.method == "POST":
        email = request.form["email"].strip().lower()
        u = db().execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        if u and u["password"] and check_password_hash(u["password"], request.form["password"]):
            set_session(u)
            return redirect(url_for("shop"))
        flash("البريد الإلكتروني أو كلمة المرور غير صحيحة.")
    return render_template("login.html", mode="login", google=GOOGLE_ON)

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form["name"].strip()
        email = request.form["email"].strip().lower()
        pw = request.form["password"]
        if len(pw) < 6:
            flash("كلمة المرور يجب أن تكون 6 أحرف على الأقل.")
        else:
            try:
                db().execute("INSERT INTO users(name,email,password) VALUES(?,?,?)",
                             (name, email, generate_password_hash(pw)))
                db().commit()
                set_session(db().execute("SELECT * FROM users WHERE email=?", (email,)).fetchone())
                return redirect(url_for("shop"))
            except sqlite3.IntegrityError:
                flash("هذا البريد مسجّل مسبقاً. سجّل الدخول بدلاً من ذلك.")
    return render_template("login.html", mode="register", google=GOOGLE_ON)

@app.route("/google")
def google_login():
    if not GOOGLE_ON:
        flash("تسجيل الدخول عبر Google غير مفعّل بعد. أضف مفاتيح Google أولاً.")
        return redirect(url_for("login"))
    return oauth.google.authorize_redirect(url_for("google_callback", _external=True))

@app.route("/google/callback")
def google_callback():
    info = oauth.google.authorize_access_token()["userinfo"]
    email = info["email"].lower()
    if not db().execute("SELECT 1 FROM users WHERE email=?", (email,)).fetchone():
        db().execute("INSERT INTO users(name,email,password) VALUES(?,?,NULL)",
                     (info.get("name", email), email))
        db().commit()
    set_session(db().execute("SELECT * FROM users WHERE email=?", (email,)).fetchone())
    return redirect(url_for("shop"))

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# ---------- المتجر ----------
@app.route("/shop")
@login_required
def shop():
    view = request.args.get("view", "all")
    q = "SELECT * FROM products" + (" WHERE old IS NOT NULL" if view == "offers" else "")
    return render_template("shop.html", products=db().execute(q).fetchall(), view=view,
                           count=sum(session.get("cart", {}).values()))

@app.route("/add/<int:pid>", methods=["POST"])
@login_required
def add(pid):
    p = get_product(pid)
    if p:
        cart = session.get("cart", {})
        cart[str(pid)] = cart.get(str(pid), 0) + 1
        session["cart"] = cart
        flash(f"أُضيف «{p['name']}» إلى السلة.")
    return redirect(request.referrer or url_for("shop"))

@app.route("/remove/<int:pid>", methods=["POST"])
@login_required
def remove(pid):
    cart = session.get("cart", {})
    cart.pop(str(pid), None)
    session["cart"] = cart
    return redirect(url_for("cart"))

@app.route("/cart")
@login_required
def cart():
    rows = cart_rows()
    return render_template("cart.html", rows=rows, stripe=STRIPE_ON,
                           total=sum(p["price"] * q for p, q in rows),
                           count=sum(q for _, q in rows))

def save_order(method, status):
    rows = cart_rows()
    total = sum(p["price"] * q for p, q in rows)
    items = "، ".join(f"{p['name']} ×{q}" for p, q in rows)
    db().execute("INSERT INTO orders(user,total,method,status,items) VALUES(?,?,?,?,?)",
                 (session["user"], total, method, status, items))
    db().commit()
    session["cart"] = {}

@app.route("/checkout/<method>", methods=["POST"])
@login_required
def checkout(method):
    rows = cart_rows()
    if not rows:
        return redirect(url_for("shop"))
    if method == "cod":  # الدفع عند الاستلام
        save_order("عند الاستلام", "قيد التجهيز")
        return render_template("done.html", count=0)
    if method == "card" and STRIPE_ON:  # الدفع بالبطاقة عبر Stripe
        s = stripe.checkout.Session.create(
            mode="payment",
            line_items=[{"quantity": q, "price_data": {
                "currency": "usd", "unit_amount": max(50, round(p["price"] / LYD_PER_USD * 100)),
                "product_data": {"name": p["name"]}}} for p, q in rows],
            success_url=url_for("paid", _external=True) + "?sid={CHECKOUT_SESSION_ID}",
            cancel_url=url_for("cart", _external=True))
        return redirect(s.url, 303)
    flash("الدفع بالبطاقة غير مفعّل بعد.")
    return redirect(url_for("cart"))

@app.route("/paid")
@login_required
def paid():
    s = stripe.checkout.Session.retrieve(request.args.get("sid", ""))
    if s.payment_status == "paid":
        save_order("بطاقة", "مدفوع")
        return render_template("done.html", count=0)
    flash("لم تكتمل عملية الدفع.")
    return redirect(url_for("cart"))

# ---------- لوحة الإدارة ----------
@app.route("/admin")
@admin_required
def admin():
    return render_template("admin.html", count=0,
        products=db().execute("SELECT * FROM products ORDER BY id DESC").fetchall(),
        orders=db().execute("SELECT * FROM orders ORDER BY id DESC LIMIT 30").fetchall())

@app.route("/admin/save", methods=["POST"])
@admin_required
def admin_save():
    f = request.form
    old = float(f["old"]) if f.get("old") else None
    vals = (f["name"], float(f["price"]), old, f["cat"], f.get("emoji") or "📦")
    if f.get("id"):
        db().execute("UPDATE products SET name=?,price=?,old=?,cat=?,emoji=? WHERE id=?", vals + (f["id"],))
    else:
        db().execute("INSERT INTO products(name,price,old,cat,emoji) VALUES(?,?,?,?,?)", vals)
    db().commit()
    return redirect(url_for("admin"))

@app.route("/admin/delete/<int:pid>", methods=["POST"])
@admin_required
def admin_delete(pid):
    db().execute("DELETE FROM products WHERE id=?", (pid,))
    db().commit()
    return redirect(url_for("admin"))

if __name__ == "__main__":
    init_db()
    app.run(debug=True)
