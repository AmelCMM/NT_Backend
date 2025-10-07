/*
require('dotenv').config();
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const nodemailer = require('nodemailer');
const helmet = require('helmet');
const xss = require('xss-clean');
const cors = require('cors');
const { body, validationResult } = require('express-validator');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const cookie = require('cookie');

const app = express();
const server = http.createServer(app);

const allowedOrigins = [
  'https://amelcmm.github.io',
  'https://nt-secure-chat.vercel.app',
  'http://localhost:3000', // For local testing
  '*'
];

// CORS configuration
app.use(cors({
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'), false);
    }
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-App-CSRF', 'X-App-Source'],
  credentials: true,
  preflightContinue: false,
  optionsSuccessStatus: 204,
}));

// Custom middleware to block non-browser clients
app.use((req, res, next) => {
  const userAgent = req.headers['user-agent'] || 'unknown';
  const appHeader = req.headers['x-app-source'];
  if (userAgent.includes('Postman') || userAgent.includes('curl') || appHeader !== 'nt-secure-chat') {
    return res.status(403).json({ error: 'Requests from this client are not allowed' });
  }
  next();
});

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { error: 'Too many requests, please try again later.' },
});
app.use(limiter);

// Middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      connectSrc: ["'self'", ...allowedOrigins],
      scriptSrc: ["'self'"],
    },
  },
}));
app.use(xss());
app.use(express.json());
app.use(express.static(__dirname + '/public'));

// CSRF Token Middleware
const generateCsrfToken = (req, res, next) => {
  try {
    if (!process.env.JWT_SECRET) {
      throw new Error('JWT_SECRET is not defined');
    }
    const csrfToken = jwt.sign(
      { ip: req.ip, userAgent: req.headers['user-agent'] || 'unknown' },
      process.env.JWT_SECRET,
      { expiresIn: '15m' }
    );
    res.cookie('csrf_token', csrfToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
    });
    res.json({ csrfToken });
  } catch (error) {
    console.error('CSRF Token Generation Error:', error.message);
    res.status(500).json({ error: 'Failed to generate CSRF token' });
  }
};

const verifyCsrfToken = (req, res, next) => {
  const csrfToken = req.headers['x-app-csrf'] || req.cookies['csrf_token'];
  if (!csrfToken) {
    return res.status(403).json({ error: 'CSRF token missing' });
  }
  try {
    const decoded = jwt.verify(csrfToken, process.env.JWT_SECRET);
    if (decoded.ip !== req.ip || decoded.userAgent !== (req.headers['user-agent'] || 'unknown')) {
      return res.status(403).json({ error: 'Invalid CSRF token' });
    }
    next();
  } catch (err) {
    console.error('CSRF Token Verification Error:', err.message);
    return res.status(403).json({ error: 'Invalid or expired CSRF token' });
  }
};

// Socket.IO Configuration
const io = new Server(server, {
  path: '/nt_backends_api/v1/socket.io',
  cors: {
    origin: (origin, callback) => {
      if (!origin || allowedOrigins.includes(origin)) {
        callback(null, true);
      } else {
        callback(new Error('Not allowed by CORS'));
      }
    },
    methods: ['GET', 'POST'],
    credentials: true,
  },
});

// Credential validation for login
const validateCredentials = [
  body('username').trim().escape().notEmpty().withMessage('Username is required').isLength({ min: 3 }).withMessage('Username must be at least 3 characters'),
  body('password').trim().notEmpty().withMessage('Password is required').isLength({ min: 8 }).withMessage('Password must be at least 8 characters')
    .matches(/^(?=.*[A-Za-z])(?=.*\d)/).withMessage('Password must contain letters and numbers'),
];

// CSRF Token Route
app.get('/nt_backends_api/v1/csrf-token', generateCsrfToken);

// Email Sending Route
app.post('/mypt/send-email', verifyCsrfToken, async (req, res) => {
  console.log('Received email request:', req.body);
  const { name, email, message } = req.body;

  if (!name || !email || !message) {
    return res.status(400).json({ error: 'Missing required fields' });
  }

  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return res.status(400).json({ error: 'Invalid email address' });
  }

  if (message.length < 30) {
    return res.status(400).json({ error: 'Message must be at least 30 characters long' });
  }

  try {
    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      },
    });

    const mailOptions = {
      from: `"${name}" <${process.env.EMAIL_USER}>`,
      to: process.env.EMAIL_USER,
      replyTo: email,
      subject: `Business Message from ${name}`,
      text: `Name: ${name}\n\nEmail: ${email}\n\nMessage: ${message}`,
      html: `
        <h2>New Contact Form Submission</h2>
        <p><strong>Name:</strong> ${name}</p>
        <p><strong>Email:</strong> ${email}</p>
        <p><strong>Message:</strong> ${message}</p>
      `,
    };

    await transporter.sendMail(mailOptions);
    res.status(200).json({ message: 'Email sent successfully' });
  } catch (error) {
    console.error('Email error:', error);
    res.status(500).json({ error: 'Error sending email. Please try again later.' });
  }
});

// Login Route
app.post('/nt_backends_api/v1/login', verifyCsrfToken, validateCredentials, (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }
  const { username, password } = req.body;

  userDatabaseOperation.verifyUser(username, password, (err, isValid) => {
    if (err) {
      return res.status(500).json({ error: 'Server error' });
    }
    if (!isValid) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    userDatabaseOperation.getUserByUsername(username, (err, user) => {
      if (err || !user) {
        return res.status(500).json({ error: 'User retrieval error' });
      }
      const token = jwt.sign(
        { id: user.id, username: user.username },
        process.env.JWT_SECRET,
        { expiresIn: '1h' }
      );
      res.json({
        message: 'Authentication successful',
        token,
        user: { id: user.id, username: user.username, publicKey: user.publicKey },
      });
    });
  });
});

// Signout Route
app.post('/nt_backends_api/v1/signout', verifyCsrfToken, (req, res) => {
  res.clearCookie('token');
  res.clearCookie('csrf_token');
  res.json({ message: 'Signed out successfully' });
});

// Create Account Route
app.post('/nt_backends_api/v1/create_account', verifyCsrfToken, validateCredentials, (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }
  const { username, password, publicKey } = req.body;
  userDatabaseOperation.addUser(username, password, publicKey, (err, user) => {
    if (err) {
      return res.status(400).json({ error: 'Username taken or error occurred' });
    }
    res.json({ message: 'User created successfully', user });
  });
});

// Test Route
app.get('/', (req, res) => {
  res.send('Backend is running');
});

// Socket.IO Authentication
io.use((socket, next) => {
  const token = socket.handshake.auth.token;
  if (!token) {
    return next(new Error('Authentication error'));
  }
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      return next(new Error('Authentication error'));
    }
    socket.user = user;
    next();
  });
});

// Socket.IO Connection Handling
const onlineUsers = {};
const messageHistory = {};

io.on('connection', (socket) => {
  const username = socket.user.username;
  onlineUsers[username] = socket.id;
  console.log(`User connected: ${username}`);

  socket.on('register', ({ publicKey }) => {
    socket.publicKey = publicKey;
    console.log(`Public key registered for ${username}: ${publicKey}`);
  });

  socket.on('private_message', ({ to, from, encrypted }) => {
    const key = [from, to].sort().join('-');
    if (!messageHistory[key]) {
      messageHistory[key] = [];
    }
    messageHistory[key].push({ sender: from, receiver: to, encrypted });
    const targetSocket = onlineUsers[to];
    if (targetSocket) {
      io.to(targetSocket).emit('receive_private', { from, encrypted });
    }
  });

  socket.on('request_public_key', (peer) => {
    const peerSocketId = onlineUsers[peer];
    if (peerSocketId) {
      const peerSocket = io.sockets.sockets.get(peerSocketId);
      socket.emit('public_key_response', { publicKey: peerSocket.publicKey });
    }
  });

  socket.on('load_history', ({ withUser }) => {
    const key = [username, withUser].sort().join('-');
    const history = messageHistory[key] || [];
    socket.emit('chat_history', { history });
  });

  socket.on('disconnect', () => {
    console.log(`User disconnected: ${username}`);
    delete onlineUsers[username];
  });
});

// Error Handling Middleware
app.use((err, req, res, next) => {
  console.error('Server Error:', err.stack);
  res.status(500).json({ error: 'Internal Server Error' });
});

// Start Server
const port = process.env.PORT || 3000;
server.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
*/




require('dotenv').config();
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const nodemailer = require('nodemailer');
const helmet = require('helmet');
const xss = require('xss-clean');
const cors = require('cors');
const { body, validationResult } = require('express-validator');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const cookie = require('cookie');

const app = express();
const server = http.createServer(app);

const allowedOrigins = [
    '*',
  'https://amelcmm.github.io',
  'https://nt-secure-chat.vercel.app'

];

// CORS configuration
app.use(cors({
  origin: (origin, callback) => {
    if (allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'), false);
    }
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-App-CSRF', 'X-App-Source'],
  credentials: true,
  optionsSuccessStatus: 204,
}));

// Custom middleware to block non-browser clients
app.use((req, res, next) => {
  const userAgent = req.headers['user-agent'] || 'unknown';
  const appHeader = req.headers['x-app-source'];
  if (userAgent.includes('Postman') || userAgent.includes('curl') || appHeader !== 'nt-secure-chat') {
    return res.status(403).json({ error: 'Requests from this client are not allowed' });
  }
  next();
});

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit to 100 requests per IP
  message: { error: 'Too many requests, please try again later.' },
});
app.use(limiter);

// Middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      connectSrc: ["'self'", ...allowedOrigins],
      scriptSrc: ["'self'"],
    },
  },
}));
app.use(xss());
app.use(express.json());
app.use(express.static(__dirname + '/public'));

// CSRF Token Middleware
const generateCsrfToken = (req, res, next) => {
  try {
    if (!process.env.JWT_SECRET) {
      throw new Error('JWT_SECRET is not defined');
    }
    const csrfToken = jwt.sign(
      { ip: req.ip, userAgent: req.headers['user-agent'] || 'unknown' },
      process.env.JWT_SECRET,
      { expiresIn: '15m' }
    );
    res.cookie('csrf_token', csrfToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
    });
    res.json({ csrfToken });
  } catch (error) {
    console.error('CSRF Token Generation Error:', error.message);
    res.status(500).json({ error: 'Failed to generate CSRF token' });
  }
};

const verifyCsrfToken = (req, res, next) => {
  const csrfToken = req.headers['x-app-csrf'] || req.cookies['csrf_token'];
  if (!csrfToken) {
    return res.status(403).json({ error: 'CSRF token missing' });
  }
  try {
    const decoded = jwt.verify(csrfToken, process.env.JWT_SECRET);
    if (decoded.ip !== req.ip || decoded.userAgent !== (req.headers['user-agent'] || 'unknown')) {
      return res.status(403).json({ error: 'Invalid CSRF token' });
    }
    next();
  } catch (err) {
    console.error('CSRF Token Verification Error:', err.message);
    return res.status(403).json({ error: 'Invalid or expired CSRF token' });
  }
};

// Socket.IO Configuration
const io = new Server(server, {
  path: '/nt_backends_api/v1/socket.io',
  cors: {
    origin: (origin, callback) => {
      if (allowedOrigins.includes(origin)) {
        callback(null, true);
      } else {
        callback(new Error('Not allowed by CORS'));
      }
    },
    methods: ['GET', 'POST'],
    credentials: true,
  },
});

// Credential validation for login
const validateCredentials = [
  body('username').trim().escape().notEmpty().withMessage('Username is required').isLength({ min: 3 }).withMessage('Username must be at least 3 characters'),
  body('password').trim().notEmpty().withMessage('Password is required').isLength({ min: 8 }).withMessage('Password must be at least 8 characters')
    .matches(/^(?=.*[A-Za-z])(?=.*\d)/).withMessage('Password must contain letters and numbers'),
];

// CSRF Token Route
app.get('/nt_backends_api/v1/csrf-token', generateCsrfToken);

// Email Sending Route
app.post('/mypt/send-email', verifyCsrfToken, async (req, res) => {
  console.log('Received email request:', req.body);
  const { name, email, message } = req.body;

  if (!name || !email || !message) {
    return res.status(400).json({ error: 'Missing required fields' });
  }

  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return res.status(400).json({ error: 'Invalid email address' });
  }

  if (message.length < 30) {
    return res.status(400).json({ error: 'Message must be at least 30 characters long' });
  }

  try {
    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      },
    });

    const mailOptions = {
      from: `"${name}" <${process.env.EMAIL_USER}>`,
      to: process.env.EMAIL_USER,
      replyTo: email,
      subject: `Business Message from ${name}`,
      text: `Name: ${name}\n\nEmail: ${email}\n\nMessage: ${message}`,
      html: `
        <h2>New Contact Form Submission</h2>
        <p><strong>Name:</strong> ${name}</p>
        <p><strong>Email:</strong> ${email}</p>
        <p><strong>Message:</strong> ${message}</p>
      `,
    };

    await transporter.sendMail(mailOptions);
    res.status(200).json({ message: 'Email sent successfully' });
  } catch (error) {
    console.error('Email error:', error.message);
    res.status(500).json({ error: 'Error sending email. Please try again later.' });
  }
});

// Login Route
app.post('/nt_backends_api/v1/login', verifyCsrfToken, validateCredentials, (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }
  const { username, password } = req.body;

  userDatabaseOperation.verifyUser(username, password, (err, isValid) => {
    if (err) {
      console.error('User verification error:', err.message);
      return res.status(500).json({ error: 'Server error' });
    }
    if (!isValid) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    userDatabaseOperation.getUserByUsername(username, (err, user) => {
      if (err || !user) {
        console.error('User retrieval error:', err?.message);
        return res.status(500).json({ error: 'User retrieval error' });
      }
      const token = jwt.sign(
        { id: user.id, username: user.username },
        process.env.JWT_SECRET,
        { expiresIn: '1h' }
      );
      res.json({
        message: 'Authentication successful',
        token,
        user: { id: user.id, username: user.username, publicKey: user.publicKey },
      });
    });
  });
});

// Signout Route
app.post('/nt_backends_api/v1/signout', verifyCsrfToken, (req, res) => {
  res.clearCookie('token');
  res.clearCookie('csrf_token');
  res.json({ message: 'Signed out successfully' });
});

// Create Account Route
app.post('/nt_backends_api/v1/create_account', verifyCsrfToken, validateCredentials, (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }
  const { username, password, publicKey } = req.body;
  userDatabaseOperation.addUser(username, password, publicKey, (err, user) => {
    if (err) {
      console.error('User creation error:', err.message);
      return res.status(400).json({ error: 'Username taken or error occurred' });
    }
    res.json({ message: 'User created successfully', user });
  });
});

// Test Route
app.get('/', (req, res) => {
  res.send('Backend is running');
});

// Socket.IO Authentication
io.use((socket, next) => {
  const token = socket.handshake.auth.token;
  if (!token) {
    return next(new Error('Authentication error'));
  }
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      console.error('Socket.IO auth error:', err.message);
      return next(new Error('Authentication error'));
    }
    socket.user = user;
    next();
  });
});

// Socket.IO Connection Handling
const onlineUsers = {};
const messageHistory = {};

io.on('connection', (socket) => {
  const username = socket.user.username;
  onlineUsers[username] = socket.id;
  console.log(`User connected: ${username}`);

  socket.on('register', ({ publicKey }) => {
    socket.publicKey = publicKey;
    console.log(`Public key registered for ${username}: ${publicKey}`);
  });

  socket.on('private_message', ({ to, from, encrypted }) => {
    const key = [from, to].sort().join('-');
    if (!messageHistory[key]) {
      messageHistory[key] = [];
    }
    messageHistory[key].push({ sender: from, receiver: to, encrypted });
    const targetSocket = onlineUsers[to];
    if (targetSocket) {
      io.to(targetSocket).emit('receive_private', { from, encrypted });
    }
  });

  socket.on('request_public_key', (peer) => {
    const peerSocketId = onlineUsers[peer];
    if (peerSocketId) {
      const peerSocket = io.sockets.sockets.get(peerSocketId);
      socket.emit('public_key_response', { publicKey: peerSocket.publicKey });
    }
  });

  socket.on('load_history', ({ withUser }) => {
    const key = [username, withUser].sort().join('-');
    const history = messageHistory[key] || [];
    socket.emit('chat_history', { history });
  });

  socket.on('disconnect', () => {
    console.log(`User disconnected: ${username}`);
    delete onlineUsers[username];
  });
});

// Error Handling Middleware
app.use((err, req, res, next) => {
  console.error('Server Error:', err.stack);
  res.status(500).json({ error: 'Internal Server Error' });
});

// Start Server
const port = process.env.PORT || 3000;
server.listen(port, () => {
  console.log(`Server running on port ${port}`);
});


