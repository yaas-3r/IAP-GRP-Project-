const WebSocket = require("ws");
let wss;

module.exports = (server) => {
    try {
        wss = new WebSocket.Server({ server });
    } catch {
        console.log("Error: Cannot start WebSocket server. Check if the HTTP server is passed correctly.");
        return null;
    }

    let clients = [];

    wss.on("connection", (ws) => {
        clients.push(ws);
        console.log("New (ws): Client connected to server!");

        ws.on("message", (data) => {
            let info;
            try {
                info = JSON.parse(data.toString());
            } catch {
                console.log("Error with received info JSON!");
                return;
            }

            switch (info.type) {
                case "StatusUpdate":
                    console.log("Type:(Status)...Status update message received!");
                    break;
                case "Chat":
                    console.log("Type:(Chat)...Chat message received.");
                    if (info.from === "Driver") {
                        console.log("Message from: DRIVER");
                        console.log(info.chat);
                    } else if (info.from === "User") {
                        console.log("Message from: USER");
                        console.log(info.chat);
                    }
                    break;
                default:
                    console.log("No message of TYPE received!");
                    break;
            }

            console.log(`info received by server:\n${JSON.stringify(info, null, 2)}`);

            clients.forEach((client) => {
                if (client !== ws && client.readyState === WebSocket.OPEN) {
                    client.send(JSON.stringify(info));
                }
            });
        });

        ws.on("close", () => {
            console.log("A (ws) websocket has disconnected!");
            clients = clients.filter(c => c !== ws);
        });
    });

    return wss;
};
