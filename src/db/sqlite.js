const fs = require('fs');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();

const dbFile = process.env.DB_FILE || path.join(__dirname, '../../data/app.db');
const dbDir = path.dirname(dbFile);

if (!fs.existsSync(dbDir)) {
  fs.mkdirSync(dbDir, { recursive: true });
}

const db = new sqlite3.Database(dbFile);

function setupDatabase() {
  db.serialize(() => {
    db.run(
      `CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'user',
        bio TEXT DEFAULT ''
      )`
    );

    db.run(
      `INSERT OR IGNORE INTO users (id, email, password_hash, role, bio)
       VALUES (1, 'admin@example.com', '5f4dcc3b5aa765d61d8327deb882cf99', 'admin', 'Welcome admin')`
    );
  });
}

if (require.main === module) {
  setupDatabase();
  console.log(`Database initialized at ${dbFile}`);
}

module.exports = { db, setupDatabase };
