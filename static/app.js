const socket = io.connect(location.protocol + '//' + document.domain + ':' + location.port);

// Join watch party room
function joinWatchParty(room) {
    socket.emit('join', { room: room });
}

// Leave watch party room
function leaveWatchParty(room) {
    socket.emit('leave', { room: room });
}

// Start Screen Share
function startScreenShare(room) {
    console.log("Attempting to start screen share for room:", room);

    if (navigator.mediaDevices && navigator.mediaDevices.getDisplayMedia) {
        navigator.mediaDevices.getDisplayMedia({ video: true })
            .then((stream) => {
                const track = stream.getVideoTracks()[0];
                console.log("Track ID:", track.id);  // Verify track is valid
                socket.emit('screenShare', { room: room, track: track.id });
            })
            .catch((error) => {
                console.error("Error starting screen share:", error);
            });
    } else {
        alert("Screen sharing is not supported in this browser.");
    }
}

// Listen for messages
socket.on('message', (msg) => {
    console.log(msg);
    alert(msg);
});

// Listen for screen share events
socket.on('screenShare', (data) => {
    console.log("Screen Share Received:", data.track);
});
