require('dotenv').config();
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const helmet = require('helmet');
const xss = require('xss-clean');
const bodyParser = require('body-parser');
const { body, validationResult } = require('express-validator');
const userDatabaseOperation = require('./UserDatabaseOperation');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(helmet());
app.use(xss());
app.use(bodyParser.json());
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  next();
});

// Credential validation
const validateCredentials = [
  body('username').trim().escape().notEmpty().withMessage('Username required').isLength({ min: 3 }).withMessage('Min 3 chars'),
  body('password').trim().notEmpty().withMessage('Password required').isLength({ min: 8 }).withMessage('Min 8 chars')
    .matches(/^(?=.*[A-Za-z])(?=.*\d)/).withMessage('Letters & numbers'),
];

// Login Route
app.post('/nt_backends_api/v1/login', validateCredentials, (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
  const { username, password } = req.body;

  userDatabaseOperation.verifyUser(username, password, (err, isValid) => {
    if (err) return res.status(500).json({ error: 'Server error' });
    if (!isValid) return res.status(401).json({ error: 'Invalid credentials' });

    userDatabaseOperation.getUserByUsername(username, (err, user) => {
      if (err || !user) return res.status(500).json({ error: 'User retrieval error' });
      const token = jwt.sign({ id: user.id, username: user.username }, process.env.JWT_SECRET || 'fallback_secret_use_env_var', { expiresIn: '1h' });
      res.json({ message: 'Authentication successful', token, user: { id: user.id, username: user.username, publicKey: user.publicKey } });
    });
  });
});

// Signout Route
app.post('/nt_backends_api/v1/signout', (req, res) => {
  res.clearCookie('token');
  res.json({ message: 'Signed out successfully' });
});

// Create Account Route
app.post('/nt_backends_api/v1/create_account', (req, res) => {
  const { username, password, publicKey } = req.body;
  userDatabaseOperation.addUser(username, password, publicKey, (err, user) => {
    if (err) return res.status(400).json({ error: 'Username taken or error occurred' });
    res.json({ message: 'User created successfully', user });
  });
});

// Start HTTP & Socket.IO
const server = http.createServer(app);
const io = new Server(server, {
  path: '/nt_backends_api/v1/socket.io',
  cors: { origin: '*', methods: ['GET','POST'] }
});

const onlineUsers = {};
const messageHistory = {}; // key: 'userA-userB'

io.use((socket, next) => {
  const token = socket.handshake.auth.token;
  if (!token) return next(new Error('Auth error'));
  jwt.verify(token, process.env.JWT_SECRET || 'fallback_secret_use_env_var', (err, user) => {
    if (err) return next(new Error('Auth error'));
    socket.user = user;
    next();
  });
});

io.on('connection', (socket) => {
  const username = socket.user.username;
  onlineUsers[username] = socket.id;

  socket.on('register', ({ publicKey }) => { socket.publicKey = publicKey; });

  socket.on('private_message', ({ to, from, encrypted }) => {
    const key = [from, to].sort().join('-');
    if (!messageHistory[key]) messageHistory[key] = [];
    messageHistory[key].push({ sender: from, receiver: to, encrypted });
    const targetSocket = onlineUsers[to];
    if (targetSocket) io.to(targetSocket).emit('receive_private', { from, encrypted });
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

  socket.on('disconnect', () => { delete onlineUsers[username]; });
});

app.use(express.static(__dirname + '/public'));

server.listen(PORT, () => console.log(`Server listening on http://localhost:${PORT}`));