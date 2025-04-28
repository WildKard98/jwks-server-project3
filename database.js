const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database('./jwks.db');

db.serialize(() => {
    db.run(`
        CREATE TABLE IF NOT EXISTS keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            publicKey TEXT NOT NULL,
            encryptedPrivateKey TEXT NOT NULL
        )
    `);

    db.run(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    `);

    db.run(`
        CREATE TABLE IF NOT EXISTS auth_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            userId INTEGER,
            timestamp TEXT,
            ip TEXT,
            FOREIGN KEY(userId) REFERENCES users(id)
        )
    `);
});

module.exports = db;
