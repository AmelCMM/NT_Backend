require("dotenv").config();
const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const bodyParser = require("body-parser");
const helmet = require("helmet");
const xss = require("xss-clean");
const rateLimit = require("express-rate-limit");
const { body, validationResult } = require("express-validator");
const quickChatView = require("./quickChatView.js");    
const initialiseDatabase = require("./initialiseDatabase.js"); // Import the database initialization module
const app = express();
const PORT = process.env.PORT || 3000;
const userDatabaseOperation = require("./UserDatabaseOperation.js"); // Import the user model


// Environment variables
const JWT_SECRET = process.env.JWT_SECRET || "fallback_secret_use_env_var";
// Rate limiting configuration
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // limit each IP to 100 requests per windowMs
});

// Security middleware
app.use(helmet());
app.use(xss());
app.use(bodyParser.json());
app.use("/signin", limiter);
app.use("/signup", limiter);

// Mock database
const users = [];


// Helper function to authenticate token
function authenticateToken(req, res, next) {
    console.log("Authenticating token...");
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

// Validation middleware
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

// Route to create new account
app.post("/signup", validateCredentials, async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const { username, password } = req.body;

    try {
        const existingUser = users.find((user) => user.username === username);
        if (existingUser) {
            return res.status(400).json({ error: "Username already exists" });
        }

        const hashedPassword = await bcrypt.hash(password, 12);
        users.push({ username, password: hashedPassword });
        res.status(201).json({ message: "Account created successfully" });
    } catch (error) {
        res.status(500).json({ error: "Server error during account creation" });
    }
});

// Route to sign in
app.post("/signin", validateCredentials, async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const { username, password } = req.body;
    console.log(`Attempting to sign in user: ${username}`);

    try {
        const user = users.find((user) => user.username === username);
        if (!user) {
            return res.status(400).json({ error: "Invalid credentials" });
        }

        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            return res.status(400).json({ error: "Invalid credentials" });
        }

        const token = jwt.sign({ username: user.username }, JWT_SECRET, {
            expiresIn: "1h",
        });

        // Set cookie with token
        res.cookie("token", token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            sameSite: "strict",
            maxAge: 3600000, // 1 hour
        });

        res.status(200).json({ message: "Authentication successful" });
    } catch (error) {
        res.status(500).json({ error: "Server error during authentication" });
    }
});

// Protected route example authenticated with JWT
app.get("/nt_backends_api/v1/getchats" ,(req, res) => {
    res.status(200).json(quickChatView);
});

// Sign out route
app.post("/signout", (req, res) => {
    res.clearCookie("token");
    res.status(200).json({ message: "Successfully signed out" });
});

app.use(express.json());

app.post("/nt_backends_api/v1/create_account", (req, res) => {
    const { username, password } = req.body;
    //Just for testing porposes use bcrypt to hash the password 
    const hashedPassword = bcrypt.hashSync(password, 30);
    // Check if the user already exists
    const existingUser = users.find((user) => user.username === username);
    
    userModel.addUser(username, password, (err, user) => {
        if (err) {
            res.status(400).json({ error: err.message });
        } else {
            res.json({ message: "User added successfully", user });
        }
    });
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ error: "Internal server error" });
});

// Start server
app.listen(PORT, () => {// Initialize the database when the server starts
    console.log(`Server running on port ${PORT}`);
});