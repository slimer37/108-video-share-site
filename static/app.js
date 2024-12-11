const socket = io.connect(location.protocol + '//' + document.domain + ':' + location.port);

// Join watch party room
function joinWatchParty(room) {
    socket.emit('join', { room: room });
}

// Leave watch party room
function leaveWatchParty(room) {
    socket.emit('leave', { room: room });
}

// Listen for messages
socket.on('message', (msg) => {
    console.log(msg);
    alert(msg);
});
