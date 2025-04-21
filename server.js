require("dotenv").config();
const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const bodyParser = require("body-parser");
const helmet = require("helmet");
const xss = require("xss-clean");
const { body, validationResult } = require("express-validator");
const quickChatView = require("./quickChatView.js");
const initialiseDatabase = require("./initialiseDatabase.js");
const app = express();
const PORT = process.env.PORT || 3000;
const userDatabaseOperation = require("./UserDatabaseOperation.js");
const socketHandler = require("./socketHandler.js");
const http = require("http");
const server = http.createServer(app);
const { Server } = require("socket.io");
const io = new Server(server, {
    path: "/nt_backends_api/v1/socket.io",
    cors: {
        origin: "*",
        methods: ["GET", "POST"]
    }
});

const JWT_SECRET = process.env.JWT_SECRET || "fallback_secret_use_env_var";

app.use(helmet());
app.use(xss());
app.use(bodyParser.json());

function authenticateToken(req, res, next) {
    const authHeader = req.headers["authorization"];
    const token = authHeader && authHeader.split(" ")[1];

    if (!token)
        return res.status(401).json({ error: "Authorization token required" });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: "Invalid or expired token" });
        req.user = user;
        next();
    });
}

const validateCredentials = [
    body("username")
        .trim()
        .escape()
        .notEmpty()
        .withMessage("Username is required")
        .isLength({ min: 3 })
        .withMessage("Username must be at least 3 characters"),

    body("password")
        .trim()
        .notEmpty()
        .withMessage("Password is required")
        .isLength({ min: 8 })
        .withMessage("Password must be at least 8 characters")
        .matches(/^(?=.*[A-Za-z])(?=.*\d)/)
        .withMessage("Password must contain letters and numbers"),
];

app.use((req, res, next) => {
    res.header("Access-Control-Allow-Origin", "*");
    res.header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE");
    res.header("Access-Control-Allow-Headers", "Content-Type");
    next();
});
app.post("/nt_backends_api/v1/login", validateCredentials, async (req, res) => {
    const { username, password } = req.body;

    try {
        userDatabaseOperation.verifyUser(username, password, (err, isValid) => {
            if (err) {
                return res.status(500).json({ error: "Server error during authentication" });
            }

            if (!isValid) {
                return res.status(401).json({ error: "Invalid username or password" });
            }

            //  Get full user details (id, username, publicKey) after verification
            userDatabaseOperation.getUserByUsername(username, (err, user) => {
                if (err || !user) {
                    return res.status(500).json({ error: "Error retrieving user data" });
                }

                // Create a JWT with user info
                const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: "1h" });

                // Send token + user data to frontend
                res.status(200).json({
                    message: "Authentication successful",
                    token,
                    user: {
                        id: user.id,
                        username: user.username,
                        publicKey: user.publicKey
                    }
                });
            });
        });
    } catch (error) {
        res.status(500).json({ error: "Server error during authentication" });
    }
});


app.post("/nt_backends_api/v1/signout", (req, res) => {
    res.clearCookie("token");
    res.status(200).json({ message: "Successfully signed out" });
});

app.use(express.json());

app.post("/nt_backends_api/v1/create_account", async (req, res) => {
    const { username, password, publicKey } = req.body;
    userDatabaseOperation.addUser(username, password, publicKey, (err, user) => {
        if (err) {
            console.error("Error adding user:", err.message);
            return res.status(400).json({ error: "Username is already taken or error occurred" });
        }
        res.json({ message: "User added successfully", user });
    });
});
//Adding the getChats
const messages = [
    { from: "alice", to: "bob", message: "Hi Bob!" },
    { from: "bob", to: "alice", message: "Hey Alice!" },
    { from: "carol", to: "bob", message: "Yo Bob" },
];
// Middleware to authenticate token
function authenticateChatToken(req, res, next) {
    const authHeader = req.headers["authorization"];
    const token = authHeader && authHeader.split(" ")[1];
    if (!token) return res.sendStatus(401);
  
    jwt.verify(token, process.env.JWT_SECRET || "fallback_secret_use_env_var", (err, user) => {
      if (err) return res.sendStatus(403);
      req.user = user;
      next();
    });
  }
app.get("/nt_backends_api/v1/getchats",authenticateChatToken, (req, res) => {
    const currentUser = req.user.username;
    console.log("Handlling chats requets")
    // Extract unique chat users for this user
    const chatUsers = {};
    messages.forEach((msg) => {
        if (msg.from === currentUser) {
            chatUsers[msg.to] = { name: msg.to, lastMessage: msg.message };
        } else if (msg.to === currentUser) {
            chatUsers[msg.from] = { name: msg.from, lastMessage: msg.message };
        }
    });
    console.log("Sending chat data to logged in user")
    res.status(200).json({ users: Object.values(chatUsers) });
});

app.get("", (req, res) => {
    res.send("Welcome to the NT Backend API!");
});

// Integrate chat-specific real-time handling
io.on("connection", (socket) => {
    console.log("New user connected to chat");
    socketHandler(io, socket);
});

app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ error: "Internal server error" });
});


server.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});