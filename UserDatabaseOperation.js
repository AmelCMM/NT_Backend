const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcryptjs");
const saltRounds = 15; // Using 15 rounds for password hashing superior to 10 rounds


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
                console.log("Users table created.");
            }
        });
    }

    addUser(username, password, callback) {
        bcrypt.hash(password, saltRounds, (err, hashedPassword) => {
            if (err) {
                return callback(err, null);
            }

            const sql = `INSERT INTO users (username, password) VALUES (?, ?)`;
            this.db.run(sql, [username, hashedPassword], function (err) {
                if (err) {
                    callback(err, null);
                } else {
                    callback(null, { id: this.lastID, username });
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
                return callback(null, false); // User not found
            }

            bcrypt.compare(password, row.password, (err, result) => {
                if (err) {
                    return callback(err, null);
                }
                callback(null, result); // Returns true if passwords match, false otherwise
            });
        });
    }
}

module.exports = new UserModel();