const express = require('express');
const http = require('http');
const { Server } = require('socket.io');

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: "*" },
});

const users = {}; // username => socket.id
const publicKeys = {}; // username => publicKey

io.on('connection', (socket) => {
  socket.on('register', ({ username, publicKey }) => {
    users[username] = socket.id;
    publicKeys[username] = publicKey;
    console.log(`${username} registered`);
  });

  socket.on('request_public_key', (target) => {
    const key = publicKeys[target];
    if (key) {
      socket.emit('public_key_response', { from: target, publicKey: key });
    }
  });

  socket.on('private_message', ({ to, from, encrypted }) => {
    const targetSocket = users[to];
    if (targetSocket) {
      io.to(targetSocket).emit('receive_private', { from, encrypted });
    }
  });

  socket.on('disconnect', () => {
    const username = Object.keys(users).find(key => users[key] === socket.id);
    if (username) {
      delete users[username];
      delete publicKeys[username];
    }
  });
});

server.listen(3000, () => {
  console.log('Server running on http://localhost:3000');
});