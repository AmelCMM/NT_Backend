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
app.use("/nt_backends_api/v1/login", limiter);
app.use("/nt_backends_api/v1/create_account", limiter);
app.use("/nt_backends_api/v1/getchats", limiter);
app.use("/signout", limiter);


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

// Route to sign in
app.post("/nt_backends_api/v1/login", validateCredentials, async (req, res) => {
    const errors = validationResult(req);
    console.log("Log in verification process has began ...");
    /*
     if (!errors.isEmpty()) {
         console.log("Validating log in details credentials... But errors found!");
         return res.status(400).json({ errors: errors.array() });
     }
     */
    const { username, password } = req.body;
    console.log(`Attempting to sign in user: ${username}`);
    try {
        // Check if user exists in the database
        //The verifyUser method in the UserDatabaseOperation class checks if the user exists and verifies the password
        // by comparing the hashed password stored in the database with the provided password.
        // If the user is found and the password matches, it returns true; otherwise, it returns false.
        userDatabaseOperation.verifyUser(username, password, (err, isValid) => {
            if (err) {
                console.error("Error verifying user:", err.message);
                return res.status(500).json({ error: "Server error during authentication" });
            }
            if (!isValid) {
                return res.status(401).json({ error: "Invalid username or password" });
            };
            // Generate JWT token 
            const token = jwt.sign({ username: username }, JWT_SECRET, {
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
            console.log("User verified successfully")
        });
    } catch (error) {
        res.status(500).json({ error: "Server error during authentication" });
    }
});

// Protected route example authenticated with JWT
app.get("/nt_backends_api/v1/getchats",authenticateToken, (req, res) => {
    res.status(200).json(quickChatView);
});

// Sign out route
app.post("/signout", (req, res) => {
    res.clearCookie("token");
    res.status(200).json({ message: "Successfully signed out" });
});

app.use(express.json());

app.post("/nt_backends_api/v1/create_account", async (req, res) => {
    const { username, password } = req.body;
    //Password is hashed before being stored in the database by the UserDatabaseOperation class
    userDatabaseOperation.addUser(username, password, (err, user) => {
        if (err) {
            res.status(400).json({ error: "Username is already taken" });
        } else {
            res.json({ message: "User added successfully", user });
        }
    }
    );
});
app.get("", (req, res) => {
    res.send("Welcome to the NT Backend API!");
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