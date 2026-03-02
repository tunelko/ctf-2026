const express = require("express")
const session = require("express-session")
const Database = require("better-sqlite3")
const crypto = require("crypto")
const fs = require("fs")

const {CipherState, bufToBig, bigToBuf} = require("./cipher")

const FLAG = fs.readFileSync("flag.txt")

const db = new Database("users.db")
const app = express()

app.set("view engine","ejs")
app.use(express.urlencoded({extended:false}))
app.use(express.static("public"))

app.use(session({
  secret: crypto.randomBytes(32).toString("hex"),
  resave:false,
  saveUninitialized:false
}))

const redirectIfLoggedIn = (req, res, next) => {
  if (req.session.uid) {
    return res.redirect("/board");
  }
  next();
};

function getCipher(uid) {
  const row = db.prepare("SELECT key FROM users WHERE id=?").get(uid)
  return new CipherState(bufToBig(row.key))
}

function updateKey(uid, cipher) {
  db.prepare("UPDATE users SET key=? WHERE id=?")
    .run(bigToBuf(cipher.key), uid)
}

app.get("/", redirectIfLoggedIn, (req, res) => res.redirect("/login"))

app.get("/register", redirectIfLoggedIn, (req, res) => res.render("register"))

app.post("/register", (req, res) => {
  const {u,p} = req.body
  const key = crypto.randomBytes(32)
  console.log(`Registering user: ${u} with key: ${bufToBig(key)}`)

  try {
    const info = db.prepare(
      "INSERT INTO users(username,password,key) VALUES(?,?,?)"
    ).run(u,p,key)

    const uid = info.lastInsertRowid
    const cipher = new CipherState(bufToBig(key))
    const ct = cipher.encrypt(FLAG)

    db.prepare(
      "INSERT INTO notes(user_id,ciphertext) VALUES(?,?)"
    ).run(uid,ct)

    updateKey(uid,cipher)
  } catch {
    return res.send("user exists")
  }
  res.redirect("/login")
})

app.get("/login", redirectIfLoggedIn, (req, res) => res.render("login"))

app.post("/login", (req, res) => {
  const {username,password} = req.body
  const row = db.prepare(
    "SELECT id FROM users WHERE username=? AND password=?"
  ).get(username,password)

  if(!row) return res.send("bad creds")

  req.session.uid = row.id
  res.redirect("/board")
})

app.get("/board", (req, res) => {
  if(!req.session.uid) return res.redirect("/login")

  const notes = db.prepare(
    "SELECT ciphertext FROM notes WHERE user_id=?"
  ).all(req.session.uid)

  res.render("board",{notes:notes.map(n=>n.ciphertext.toString("hex"))})
})

app.post("/board", (req, res) => {
  if(!req.session.uid) return res.redirect("/login")

  const noteText = req.body.note ? req.body.note.trim() : "";

  if (noteText.length === 0) {
    return res.redirect("/board");
  }

  const note = Buffer.from(noteText)
  const cipher = getCipher(req.session.uid)
  
  cipher.reseed(note)
  const ct = cipher.encrypt(note)

  db.prepare(
    "INSERT INTO notes(user_id,ciphertext) VALUES(?,?)"
  ).run(req.session.uid, ct)

  updateKey(req.session.uid, cipher)
  
  res.redirect("/board")
})

app.get("/logout", (req, res) => {
  req.session.destroy((err) => {
    res.redirect("/login");
  });
});

app.listen(3000,()=>console.log("listening on 3000"))