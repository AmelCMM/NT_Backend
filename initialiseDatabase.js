const sqlite3 = require("sqlite3").verbose();

class Database {
    constructor() {
        this.db = new sqlite3.Database("chat.db", (err) => {
            if (err) {
                console.error("Error opening database:", err.message);
            } else {
                console.log("Connected to SQLite database.");
                this.createTables();
            }
        });
    }

    createTables() {
        // Create Users table
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

        // Create Chats table
        this.db.run(`CREATE TABLE IF NOT EXISTS chats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_id INTEGER NOT NULL,
            receiver_id INTEGER NOT NULL,
            message TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (sender_id) REFERENCES users(id),
            FOREIGN KEY (receiver_id) REFERENCES users(id)
        )`, (err) => {
            if (err) {
                console.error("Error creating chats table:", err.message);
            } else {
                console.log("Chats table created.");
            }
        });
    }
}

module.exports = new Database();