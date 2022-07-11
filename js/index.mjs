/* -*- indent-tabs-mode: nil; tab-width: 2; -*- */
/* vim: set ts=2 sw=2 et ai : */

import "es-first-aid";
import * as ed from "@noble/ed25519";

(async () => {
  //
  const privateKey = ed.utils.randomPrivateKey();
  const publicKey = await ed.getPublicKey(privateKey);
  const message = {
    type: "register",
  };
  const json = JSON.stringify(message);
  const data = firstAid.encodeString(json);
  const signature = await ed.sign(data, privateKey);
  const signedMessage = {
    type: 'signed_envelope',
    algo: 'sign-ed25519',
    data: firstAid.encodeBase64(data),
    public_key: firstAid.encodeBase64(publicKey),
    signature: firstAid.encodeBase64(signature),
  };
  console.log(JSON.stringify(signedMessage));
})();
