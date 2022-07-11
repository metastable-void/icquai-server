// -*- indent-tabs-mode: nil; tab-width: 2; -*-
// vim: set ts=2 sw=2 et ai :

extern crate icquai_server;
extern crate base64;
extern crate serde_json;

use std::io;
use std::io::Read;

use icquai_server::VerifiedData;

fn main() -> io::Result<()> {
  //
  let mut buffer = String::new();
  let mut stdin = io::stdin();
  stdin.read_to_string(&mut buffer)?;
  let verified_data: VerifiedData = VerifiedData::from_json(&buffer).unwrap();
  match verified_data {
    VerifiedData { data, public_key } => {
      println!("Verified message: {}, public_key = {}", String::from_utf8(data).unwrap(), public_key);
    }
  }
  Ok(())
}
