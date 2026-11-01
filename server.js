const express = require("express");
const session = require("express-session");
const SQLiteStore = require("connect-sqlite3")(session);
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcryptjs");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;
const SESSION_SECRET = process.env.SESSION_SECRET || "development-only-change-this-secret";

const db = new sqlite3.Database(path.join(__dirname, "users.db"));
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
});

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.urlencoded({ extended: false, limit: "10kb" }));
app.use(express.static(path.join(__dirname, "public")));
app.use(session({
  store: new SQLiteStore({ db: "sessions.db", dir: __dirname }),
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: "strict", secure: false, maxAge: 1000 * 60 * 60 }
}));

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: "Too many login attempts. Please try again after 15 minutes."
});

function escapeHtml(value = "") {
  return String(value).replace(/[&<>"']/g, ch => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  })[ch]);
}
function page(title, body, user = null) {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>${escapeHtml(title)} | Secure Login</title><link rel="stylesheet" href="/style.css"></head>
  <body><header><a class="brand" href="/">Secure<span>Login</span></a>
  <nav>${user ? `<span class="nav-user">Hi, ${escapeHtml(user.name)}</span><form method="post" action="/logout"><button class="nav-button">Log out</button></form>` : `<a href="/login">Login</a><a href="/register">Register</a>`}</nav></header>
  <main>${body}</main><footer>Secure Login System · Passwords are stored as bcrypt hashes</footer></body></html>`;
}
function message(text, type = "error") {
  return `<p class="message ${type}">${escapeHtml(text)}</p>`;
}

app.get("/", (req, res) => {
  if (req.session.user) {
    return res.send(page("Dashboard", `<section class="card"><p class="eyebrow">ACCOUNT</p><h1>Welcome, ${escapeHtml(req.session.user.name)}!</h1><p>You are successfully logged in.</p><p class="muted">Your session is active. Use the Log out button to end it securely.</p></section>`, req.session.user));
  }
  res.send(page("Home", `<section class="card hero"><p class="eyebrow">DEMO APPLICATION</p><h1>Simple. Secure. Reliable.</h1><p>Create an account and sign in using securely hashed passwords.</p><div class="actions"><a class="button" href="/register">Create account</a><a class="button secondary" href="/login">Sign in</a></div></section>`));
});

app.get("/register", (req, res) => res.send(page("Register", `<section class="card"><p class="eyebrow">GET STARTED</p><h1>Create account</h1>
<form method="post" action="/register" class="form">
<label>Full name<input name="name" required minlength="2" maxlength="60" autocomplete="name"></label>
<label>Email address<input name="email" type="email" required maxlength="254" autocomplete="email"></label>
<label>Password<input name="password" type="password" required minlength="8" maxlength="72" autocomplete="new-password"></label>
<p class="hint">Use at least 8 characters. Passwords are hashed with bcrypt before storage.</p>
<button class="button" type="submit">Register</button></form><p class="below">Already registered? <a href="/login">Sign in</a></p></section>`)));

app.post("/register", async (req, res) => {
  const name = (req.body.name || "").trim();
  const email = (req.body.email || "").trim().toLowerCase();
  const password = req.body.password || "";
  if (name.length < 2 || name.length > 60 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || password.length < 8 || password.length > 72) {
    return res.status(400).send(page("Register", `<section class="card"><h1>Create account</h1>${message("Enter a valid name and email. Password must be 8–72 characters.")}<a href="/register">Try again</a></section>`));
  }
  try {
    const hash = await bcrypt.hash(password, 12);
    db.run("INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)", [name, email, hash], function(err) {
      if (err) {
        const text = err.message.includes("UNIQUE") ? "An account with this email already exists." : "Could not create account.";
        return res.status(400).send(page("Register", `<section class="card"><h1>Create account</h1>${message(text)}<a href="/register">Try again</a></section>`));
      }
      req.session.user = { id: this.lastID, name, email };
      res.redirect("/");
    });
  } catch {
    res.status(500).send(page("Error", `<section class="card">${message("Something went wrong. Please try again.")}</section>`));
  }
});

app.get("/login", (req, res) => res.send(page("Login", `<section class="card"><p class="eyebrow">WELCOME BACK</p><h1>Sign in</h1>
<form method="post" action="/login" class="form">
<label>Email address<input name="email" type="email" required autocomplete="email"></label>
<label>Password<input name="password" type="password" required autocomplete="current-password"></label>
<button class="button" type="submit">Login</button></form><p class="below">New here? <a href="/register">Create an account</a></p></section>`)));

app.post("/login", loginLimiter, (req, res, next) => {
  const email = (req.body.email || "").trim().toLowerCase();
  const password = req.body.password || "";
  if (!email || !password || password.length > 72) {
    return res.status(400).send(page("Login", `<section class="card"><h1>Sign in</h1>${message("Enter your email and password.")}<a href="/login">Try again</a></section>`));
  }
  db.get("SELECT id, name, email, password_hash FROM users WHERE email = ?", [email], async (err, user) => {
    if (err) return next(err);
    const valid = user && await bcrypt.compare(password, user.password_hash);
    if (!valid) return res.status(401).send(page("Login", `<section class="card"><h1>Sign in</h1>${message("Invalid email or password.")}<a href="/login">Try again</a></section>`));
    req.session.regenerate(regenerateErr => {
      if (regenerateErr) return next(regenerateErr);
      req.session.user = { id: user.id, name: user.name, email: user.email };
      req.session.save(saveErr => saveErr ? next(saveErr) : res.redirect("/"));
    });
  });
});

app.post("/logout", (req, res, next) => {
  req.session.destroy(err => {
    if (err) return next(err);
    res.clearCookie("connect.sid");
    res.redirect("/login");
  });
});

app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).send(page("Server error", `<section class="card"><h1>Server error</h1>${message("An unexpected error occurred.")}</section>`));
});

app.listen(PORT, () => console.log(`Secure Login System running at http://localhost:${PORT}`));
