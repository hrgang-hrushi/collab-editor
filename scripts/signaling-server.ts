// Lightweight, ultra-fast WebRTC signaling server for Crex P2P mesh
// Compatible with Bun and Node.js
// Routes WebRTC SDP offers/answers & ICE candidates with sub-millisecond dispatch

const port = Number(process.env.SIGNALING_PORT || 4444);

// Map topic string -> Set of WebSocket clients
const topics = new Map<string, Set<any>>();

function send(ws: any, message: any) {
  try {
    if (ws.readyState === 1 /* OPEN */) {
      ws.send(JSON.stringify(message));
    }
  } catch (err) {
    try {
      ws.close();
    } catch {
      // ignore
    }
  }
}

declare const Bun: any;

// Bun native WebSocket server implementation
if (typeof Bun !== "undefined") {
  const server = Bun.serve({
    port,
    fetch(req: any, server: any) {
      // Upgrade WebSocket handshakes first
      const upgraded = server.upgrade(req, {
        data: { subscribedTopics: new Set<string>() },
      });
      if (upgraded) return undefined;

      const url = new URL(req.url);
      if (url.pathname === "/health" || url.pathname === "/") {
        return new Response("CREX_SIGNALING_OK // 0PX_RADIUS // ZERO_COLOR", {
          headers: { "Content-Type": "text/plain" },
        });
      }
      return new Response("Upgrade required", { status: 426 });
    },
    websocket: {
      open(ws: any) {
        // Connected
      },
      message(ws: any, rawMessage: any) {
        let msg: any;
        try {
          msg = typeof rawMessage === "string" ? JSON.parse(rawMessage) : JSON.parse(new TextDecoder().decode(rawMessage));
        } catch {
          return;
        }

        if (!msg || !msg.type) return;

        switch (msg.type) {
          case "subscribe": {
            const list = Array.isArray(msg.topics) ? msg.topics : [];
            for (const topic of list) {
              if (typeof topic === "string") {
                let set = topics.get(topic);
                if (!set) {
                  set = new Set();
                  topics.set(topic, set);
                }
                set.add(ws);
                ws.data.subscribedTopics.add(topic);
              }
            }
            break;
          }
          case "unsubscribe": {
            const list = Array.isArray(msg.topics) ? msg.topics : [];
            for (const topic of list) {
              const set = topics.get(topic);
              if (set) {
                set.delete(ws);
                if (set.size === 0) topics.delete(topic);
              }
              ws.data.subscribedTopics.delete(topic);
            }
            break;
          }
          case "publish": {
            if (msg.topic) {
              const set = topics.get(msg.topic);
              if (set) {
                msg.clients = set.size;
                for (const client of set) {
                  if (client !== ws) {
                    send(client, msg);
                  }
                }
              }
            }
            break;
          }
          case "ping": {
            send(ws, { type: "pong" });
            break;
          }
        }
      },
      close(ws: any) {
        for (const topic of ws.data?.subscribedTopics || []) {
          const set = topics.get(topic);
          if (set) {
            set.delete(ws);
            if (set.size === 0) topics.delete(topic);
          }
        }
        ws.data?.subscribedTopics?.clear();
      },
    },
  });

  console.log(`[Crex Signaling Engine] Bun native P2P broker active on :${server.port}`);
} else {
  // Node.js fallback using ws package
  const http = require("http");
  const { WebSocketServer } = require("ws");

  const server = http.createServer((_: any, res: any) => {
    res.writeHead(200, { "Content-Type": "text/plain" });
    res.end("CREX_SIGNALING_OK // NODE_FALLBACK");
  });

  const wss = new WebSocketServer({ noServer: true });

  wss.on("connection", (ws: any) => {
    const subscribed = new Set<string>();

    ws.on("message", (raw: any) => {
      let msg: any;
      try {
        msg = JSON.parse(raw.toString());
      } catch {
        return;
      }
      if (!msg || !msg.type) return;

      if (msg.type === "subscribe") {
        for (const t of msg.topics || []) {
          if (!topics.has(t)) topics.set(t, new Set());
          topics.get(t)!.add(ws);
          subscribed.add(t);
        }
      } else if (msg.type === "unsubscribe") {
        for (const t of msg.topics || []) {
          topics.get(t)?.delete(ws);
          subscribed.delete(t);
        }
      } else if (msg.type === "publish" && msg.topic) {
        const subs = topics.get(msg.topic);
        if (subs) {
          msg.clients = subs.size;
          for (const c of subs) {
            if (c !== ws) send(c, msg);
          }
        }
      } else if (msg.type === "ping") {
        send(ws, { type: "pong" });
      }
    });

    ws.on("close", () => {
      for (const t of subscribed) {
        topics.get(t)?.delete(ws);
        if (topics.get(t)?.size === 0) topics.delete(t);
      }
      subscribed.clear();
    });
  });

  server.on("upgrade", (request: any, socket: any, head: any) => {
    wss.handleUpgrade(request, socket, head, (ws: any) => {
      wss.emit("connection", ws, request);
    });
  });

  server.listen(port, () => {
    console.log(`[Crex Signaling Engine] Node fallback active on :${port}`);
  });
}
