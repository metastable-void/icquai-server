// -*- indent-tabs-mode: nil; tab-width: 2; -*-
// vim: set ts=2 sw=2 et ai :

extern crate base64;
extern crate serde_json;

use ed25519::Signature;
use ed25519_dalek::{Verifier, PublicKey};

pub type PublicKeyBase64 = String;

pub enum IcquaiMessage {
  Unknown,
  Register {
    nonce: String,
  },
  KeepAlive,
  Forward {
    recipient: PublicKeyBase64,
  },
  Bounce {
    recipient: PublicKeyBase64,
  },
  Signed {
    signer: PublicKeyBase64,
    message: Box<Self>,
  }
}

impl IcquaiMessage {
    /// Returns `true` if the message is [`Signed`].
    ///
    /// [`Signed`]: Message::Signed
    #[must_use]
    pub fn is_signed(&self) -> bool {
        matches!(self, Self::Signed { .. })
    }

    pub fn from_json(json: &str) -> Self {
      let json_value: serde_json::Value;
      if let Ok(json) = serde_json::from_str(&json) {
        json_value = json;
      } else {
        return IcquaiMessage::Unknown
      }
      let message_type: String;
      if let Some(str) = &json_value["type"].as_str() {
        message_type = str.to_string();
      } else {
        return IcquaiMessage::Unknown
      }
      match message_type.as_str() {
        "register" => {
          let nonce: String;
          if let Some(str) = &json_value["nonce"].as_str() {
            nonce = str.to_string();
          } else {
            return IcquaiMessage::Unknown
          }
          return IcquaiMessage::Register { nonce }
        }
        "keep_alive" => {
          return IcquaiMessage::KeepAlive
        }
        "forward" => {
          let recipient: String;
          if let Some(str) = &json_value["recipient"].as_str() {
            recipient = str.to_string();
          } else {
            return IcquaiMessage::Unknown
          }
          return IcquaiMessage::Forward { recipient: recipient }
        }
        "bounce" => {
          let recipient: String;
          if let Some(str) = &json_value["recipient"].as_str() {
            recipient = str.to_string();
          } else {
            return IcquaiMessage::Unknown
          }
          return IcquaiMessage::Bounce { recipient: recipient }
        }
        "signed_envelope" => {
          if json_value["algo"] != "sign-ed25519" {
            return IcquaiMessage::Unknown
          }
          let base64_data: String;
          if let Some(str) = &json_value["data"].as_str() {
            base64_data = str.to_string();
          } else {
            return IcquaiMessage::Unknown
          }
          let base64_public_key: String;
          if let Some(str) = &json_value["public_key"].as_str() {
            base64_public_key = str.to_string();
          } else {
            return IcquaiMessage::Unknown
          }
          let base64_signature: String;
          if let Some(str) = &json_value["signature"].as_str() {
            base64_signature = str.to_string();
          } else {
            return IcquaiMessage::Unknown
          }
          let data: Vec<u8>;
          if let Ok(v) = base64::decode(&base64_data) {
            data = v;
          } else {
            return IcquaiMessage::Unknown
          }
          let public_key_bytes: Vec<u8>;
          if let Ok(v) = base64::decode(&base64_public_key) {
            public_key_bytes = v;
          } else {
            return IcquaiMessage::Unknown
          }
          let signature_bytes: Vec<u8>;
          if let Ok(v) = base64::decode(&base64_signature) {
            signature_bytes = v;
          } else {
            return IcquaiMessage::Unknown
          }
          let signature: Signature;
          if let Ok(sig) = Signature::from_bytes(&signature_bytes) {
            signature = sig;
          } else {
            return IcquaiMessage::Unknown
          }
          let public_key: PublicKey;
          if let Ok(p) = PublicKey::from_bytes(&public_key_bytes) {
            public_key = p;
          } else {
            return IcquaiMessage::Unknown
          }
          let encoded_public_key: String = base64::encode(&public_key_bytes);
          let payload: String;
          if let Ok(str) = String::from_utf8(data.clone()) {
            payload = str;
          } else {
            return IcquaiMessage::Unknown
          }
          if public_key.verify(&data, &signature).is_ok() {
            return IcquaiMessage::Signed { signer: encoded_public_key, message: Box::new(IcquaiMessage::from_json(&payload)) }
          } else {
            return IcquaiMessage::Unknown
          }
        }
        _ => {
          return IcquaiMessage::Unknown
        }
      }
    }
}
