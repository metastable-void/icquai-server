// -*- indent-tabs-mode: nil; tab-width: 2; -*-
// vim: set ts=2 sw=2 et ai :

extern crate icquai_server;
extern crate base64;
extern crate serde_json;

use std::io;
use std::io::Read;
use serde_json::Value;
use ed25519::Signature;
use ed25519_dalek::{Verifier, PublicKey};

fn main() -> io::Result<()> {
  //
  let mut buffer = String::new();
  let mut stdin = io::stdin();
  stdin.read_to_string(&mut buffer)?;
  let v: Value = serde_json::from_str(&buffer).unwrap();
  assert!(v["algo"] == "sign-ed25519");
  let public_key = if let Value::String(str) = &v["public_key"] {
    Ok(str)
  } else {
    Err("public_key must be String".to_string())
  }.unwrap();
  let data = if let Value::String(str) = &v["data"] {
    Ok(str)
  } else {
    Err("data must be String".to_string())
  }.unwrap();
  let signature = if let Value::String(str) = &v["signature"] {
    Ok(str)
  } else {
    Err("signature must be String".to_string())
  }.unwrap();
  let public_key_bytes = base64::decode(public_key).unwrap();
  let data = base64::decode(data).unwrap();
  let signature_bytes = base64::decode(signature).unwrap();
  let public_key: PublicKey = PublicKey::from_bytes(&public_key_bytes).unwrap();
  let signature = Signature::from_bytes(&signature_bytes).unwrap();
  assert!(public_key.verify(&data, &signature).is_ok());
  println!("Verified message: {}", String::from_utf8(data).unwrap());
  Ok(())
}
