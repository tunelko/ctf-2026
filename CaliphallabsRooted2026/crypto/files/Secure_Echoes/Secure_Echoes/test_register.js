const Database = require("better-sqlite3");
const crypto = require("crypto");
const path = "/tmp/test_users.db";

// Clean up
try { require("fs").unlinkSync(path); } catch {}

const db = new Database(path);
db.exec("CREATE TABLE users(id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password TEXT, key BLOB)");
db.exec("CREATE TABLE notes(id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, ciphertext BLOB)");

// Test: what happens when you insert undefined values?
const key = crypto.randomBytes(32);
try {
  const info = db.prepare("INSERT INTO users(username,password,key) VALUES(?,?,?)").run(undefined, undefined, key);
  console.log("Inserted with undefined:", info);

  // Can we login with this user?
  const row = db.prepare("SELECT id FROM users WHERE username=? AND password=?").get(undefined, undefined);
  console.log("Login with undefined:", row);

  // What about login with NULL?
  const row2 = db.prepare("SELECT id FROM users WHERE username IS NULL AND password IS NULL").get();
  console.log("Login with IS NULL:", row2);

  // Read back the user
  const user = db.prepare("SELECT * FROM users WHERE id=?").get(info.lastInsertRowid);
  console.log("User data:", user);
  console.log("Username:", JSON.stringify(user.username), "type:", typeof user.username);
  console.log("Password:", JSON.stringify(user.password), "type:", typeof user.password);
} catch(e) {
  console.log("Error:", e.message);
}

// Now test: what if we register with u=undefined, p=undefined?
// better-sqlite3 treats undefined as NULL for SQL parameters.
// So username=NULL, password=NULL.
// But username has UNIQUE constraint - can we insert NULL twice?
const key2 = crypto.randomBytes(32);
try {
  const info2 = db.prepare("INSERT INTO users(username,password,key) VALUES(?,?,?)").run(undefined, undefined, key2);
  console.log("Second insert with undefined:", info2);
  // In SQL, NULL is not equal to NULL, so UNIQUE constraint allows multiple NULLs!
  console.log("Multiple NULL usernames allowed!");
} catch(e) {
  console.log("Second insert error:", e.message);
}

// Now: can we LOGIN with these NULL-username accounts?
// Login does: SELECT id FROM users WHERE username=? AND password=?
// With undefined/NULL parameters: WHERE username IS NULL... no wait.
// better-sqlite3 binds undefined as NULL. But SQL NULL = NULL is FALSE!
// So WHERE username = NULL is always FALSE in SQL.
const row3 = db.prepare("SELECT id FROM users WHERE username=? AND password=?").get(null, null);
console.log("Login with null params:", row3);
// This should be undefined (no match) because NULL = NULL is false in SQL!

// So: we can CREATE accounts with NULL username/password but NEVER login to them.
// This means: we can create accounts where FLAG is encrypted,
// but we can never access the board for those accounts.
// Not useful.

db.close();
