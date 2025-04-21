const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcryptjs");
const saltRounds = 15;

class UserModel {
    constructor() {
        this.db = new sqlite3.Database("chat.db", (err) => {
            if (err) {
                console.error("Error opening database:", err.message);
            } else {
                console.log("Connected to SQLite database.");
                this.createTable();
            }
        });
    }

    createTable() {
        this.db.run(`CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )`, (err) => {
            if (err) {
                console.error("Error creating users table:", err.message);
            } else {
                console.log("Users table ready.");

                // Try to add publicKey column if not already present
                this.db.run(`ALTER TABLE users ADD COLUMN publicKey TEXT`, (err) => {
                    if (err && !err.message.includes("duplicate column name")) {
                        console.error("Error adding publicKey column:", err.message);
                    } else {
                        console.log("publicKey column ensured.");
                    }
                });
            }
        });
    }

    addUser(username, password, publicKey, callback) {
        bcrypt.hash(password, saltRounds, (err, hashedPassword) => {
            if (err) {
                return callback(err, null);
            }

            const sql = `INSERT INTO users (username, password, publicKey) VALUES (?, ?, ?)`;
            this.db.run(sql, [username, hashedPassword, publicKey], function (err) {
                if (err) {
                    callback(err, null);
                } else {
                    callback(null, { id: this.lastID, username, publicKey });
                }
            });
        });
    }

    verifyUser(username, password, callback) {
        const sql = `SELECT password FROM users WHERE username = ?`;
        this.db.get(sql, [username], (err, row) => {
            if (err) {
                return callback(err, null);
            }

            if (!row) {
                return callback(null, false);
            }

            bcrypt.compare(password, row.password, (err, result) => {
                if (err) {
                    return callback(err, null);
                }
                callback(null, result);
            });
        });
    }

    getUserByUsername(username, callback) {
        const sql = `SELECT id, username, publicKey FROM users WHERE username = ?`;
        this.db.get(sql, [username], (err, row) => {
            if (err) {
                return callback(err, null);
            }
            callback(null, row);
        });
    }

    getAllUsers(callback) {
        const sql = `SELECT id, username, publicKey FROM users`;
        this.db.all(sql, [], (err, rows) => {
            if (err) {
                return callback(err, null);
            }
            callback(null, rows);
        });
    }
}

module.exports = new UserModel();
