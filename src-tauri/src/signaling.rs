use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc::{self, UnboundedSender};
use tokio_tungstenite::{accept_async, tungstenite::Message};

type Subscriber = UnboundedSender<String>;
type Topics = Arc<Mutex<HashMap<String, HashMap<u64, Subscriber>>>>;
static NEXT_CLIENT_ID: AtomicU64 = AtomicU64::new(1);

pub fn start_local_relay() {
    tauri::async_runtime::spawn(async {
        // Bind only to loopback. If another Crux instance or a development
        // relay already owns the port, its server can serve both clients.
        let ipv6 = TcpListener::bind("[::1]:4444").await.ok();
        let ipv4 = TcpListener::bind("127.0.0.1:4444").await.ok();
        if ipv6.is_none() && ipv4.is_none() {
            return;
        }

        let topics: Topics = Arc::new(Mutex::new(HashMap::new()));
        if let Some(listener) = ipv6 {
            tauri::async_runtime::spawn(accept_connections(listener, topics.clone()));
        }
        if let Some(listener) = ipv4 {
            tauri::async_runtime::spawn(accept_connections(listener, topics));
        }
    });
}

async fn accept_connections(listener: TcpListener, topics: Topics) {
    while let Ok((stream, _)) = listener.accept().await {
        tauri::async_runtime::spawn(handle_connection(stream, topics.clone()));
    }
}

async fn handle_connection(stream: TcpStream, topics: Topics) {
    let Ok(socket) = accept_async(stream).await else { return };
    let client_id = NEXT_CLIENT_ID.fetch_add(1, Ordering::Relaxed);
    let (mut writer, mut reader) = socket.split();
    let (sender, mut outgoing) = mpsc::unbounded_channel::<String>();
    let write_task = tauri::async_runtime::spawn(async move {
        while let Some(text) = outgoing.recv().await {
            if writer.send(Message::Text(text.into())).await.is_err() { break; }
        }
    });
    let mut subscriptions = HashSet::new();

    while let Some(Ok(message)) = reader.next().await {
        let Message::Text(text) = message else { continue };
        let Ok(request) = serde_json::from_str::<Value>(&text) else { continue };
        match request.get("type").and_then(Value::as_str) {
            Some("subscribe") => {
                if let Some(names) = request.get("topics").and_then(Value::as_array) {
                    let mut map = topics.lock().unwrap();
                    for name in names.iter().filter_map(Value::as_str) {
                        map.entry(name.to_owned()).or_default().insert(client_id, sender.clone());
                        subscriptions.insert(name.to_owned());
                    }
                }
            }
            Some("unsubscribe") => {
                if let Some(names) = request.get("topics").and_then(Value::as_array) {
                    let mut map = topics.lock().unwrap();
                    for name in names.iter().filter_map(Value::as_str) {
                        if let Some(peers) = map.get_mut(name) { peers.remove(&client_id); }
                        subscriptions.remove(name);
                    }
                }
            }
            Some("publish") => {
                if let Some(name) = request.get("topic").and_then(Value::as_str) {
                    let peers = {
                        let map = topics.lock().unwrap();
                        map.get(name).map(|subscribers| subscribers.values().cloned().collect::<Vec<_>>())
                    };
                    if let Some(peers) = peers {
                        let notification = json!({
                            "type": "publish",
                            "topic": name,
                            "data": request.get("data").cloned().unwrap_or(Value::Null),
                            "clients": peers.len()
                        }).to_string();
                        for peer in peers { let _ = peer.send(notification.clone()); }
                    }
                }
            }
            Some("ping") => { let _ = sender.send(json!({"type": "pong"}).to_string()); }
            _ => {}
        }
    }

    {
        let mut map = topics.lock().unwrap();
        for name in subscriptions {
            if let Some(peers) = map.get_mut(&name) {
                peers.remove(&client_id);
                if peers.is_empty() { map.remove(&name); }
            }
        }
    }
    write_task.abort();
}
