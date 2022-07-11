// -*- indent-tabs-mode: nil; tab-width: 2; -*-
// vim: set ts=2 sw=2 et ai :

use std::{
  collections::HashMap,
  env,
  io::Error as IoError,
  net::SocketAddr,
  sync::{Arc, Mutex},
};

use futures_channel::mpsc::{unbounded, UnboundedSender};
use futures_util::{future, pin_mut, stream::TryStreamExt, StreamExt};

use tokio::net::{TcpListener, TcpStream};
use tungstenite::protocol::Message;

use log::info;

use icquai_server::IcquaiMessage;

use serde_json::json;

type Tx = UnboundedSender<Message>;
type PubKeyMap = Arc<Mutex<HashMap<String, Tx>>>;

async fn handle_connection(pubkey_map: PubKeyMap, raw_stream: TcpStream, addr: SocketAddr) {
  //info!("Incoming TCP connection from: {}", addr);

  let ws_stream = tokio_tungstenite::accept_async(raw_stream)
    .await
    .expect("Error during the websocket handshake occurred");
  info!("WebSocket connection established: {}", addr);

  // Insert the write part of this peer to the peer map.
  let (tx, rx) = unbounded();

  let (outgoing, incoming) = ws_stream.split();

  let maybe_pubkey: Mutex<Option<String>> = Mutex::new(None);

  let broadcast_incoming = incoming.try_filter(|msg| {
    future::ready(msg.is_text())
  }).try_for_each(|msg| {
    let text = msg.clone().into_text().unwrap();
    let message = IcquaiMessage::from_json(&text);
    match &message {
      IcquaiMessage::Signed { signer, message } => {
        // signed message
        match message.as_ref() {
          IcquaiMessage::Register => {
            let mut map = pubkey_map.lock().unwrap();
            let _ = maybe_pubkey.lock().unwrap().insert(signer.to_owned());
            map.insert(signer.to_owned(), tx.clone());
            info!("Registered: {}", signer);
          }
          IcquaiMessage::Forward { recipient } => {
            let peers = pubkey_map.lock().unwrap();
            let recipients =
              peers.iter().filter(|(peer_pubkey, _)| peer_pubkey.as_str() == recipient.as_str()).map(|(_, ws_sink)| ws_sink);
            
            info!("Forwarding message to: {}", recipient);
            
            let mut sent_count = 0;
            for recp in recipients {
              sent_count += 1;
              recp.unbounded_send(msg.clone()).unwrap();
            }

            if sent_count < 1 {
              let bounced = json!({
                "type": "bounce",
                "recipient": recipient.to_owned(),
              });
              tx.unbounded_send(Message::Text(bounced.to_string())).unwrap();
            }
          }
          _ => ()
        }
      }
      _ => () // ignore unsigned data
    }

    future::ok(())
  });

  let receive_from_others = rx.map(Ok).forward(outgoing);

  pin_mut!(broadcast_incoming, receive_from_others);
  future::select(broadcast_incoming, receive_from_others).await;

  info!("{} disconnected", &addr);
  let pubkey = maybe_pubkey.lock().unwrap().to_owned();
  match pubkey {
    Some(str) => {
      pubkey_map.lock().unwrap().remove(&str);
    }
    None => ()
  }
}

#[tokio::main]
async fn main() -> Result<(), IoError> {
  let addr = env::args().nth(1).unwrap_or_else(|| "127.0.0.1:8080".to_string());

  let pubkey_map = PubKeyMap::new(Mutex::new(HashMap::new()));

  let try_socket = TcpListener::bind(&addr).await;
  let listener = try_socket.expect("Failed to bind");
  info!("Listening on: {}", addr);

  while let Ok((stream, addr)) = listener.accept().await {
    tokio::spawn(handle_connection(pubkey_map.clone(), stream, addr));
  }

  Ok(())
}
