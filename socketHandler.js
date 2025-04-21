const userDatabaseOperation = require("./UserDatabaseOperation.js"); // Import the user model

const socketHandler = (io) => {
  io.on('connection', (socket) => {
    socket.on('register', ({ username, publicKey }) => {
      socket.username = username;
      socket.publicKey = publicKey;
      socket.broadcast.emit('user_online', { username });
    });

    socket.on('request_public_key', (targetUsername) => {
      const user = getUserByUsername(targetUsername); 
      if (!user) return;
      socket.emit('public_key_response', { publicKey: user.publicKey });
        userDatabaseOperation.getUserByUsername(targetUsername, (err, user) => {
            if (err) {
            console.error(err);
            return;
            }
            if (!user) return;
            socket.emit('public_key_response', { from: targetUsername, publicKey: user.publicKey });
        })
    });

    socket.on('private_message', ({ to, from, encrypted }) => {
      const targetSocket = [...io.sockets.sockets.values()].find(
        s => s.username === to
      );
      if (targetSocket) {
        targetSocket.emit('receive_private', { from, encrypted });
      }
    });

    socket.on('disconnect', () => {
      console.log('User disconnected');
    });
  });
};

module.exports = socketHandler;