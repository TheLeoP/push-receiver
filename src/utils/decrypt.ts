import crypto from "crypto";
// @ts-ignore: this library does not include types
import * as ece from "http_ece";

import type * as Types from "../types.js";
import { mcs_proto } from "../protos.js";
import { debug } from "./logger.js";

// https://tools.ietf.org/html/draft-ietf-webpush-encryption-03
export default function decrypt<T = Types.MessageEnvelope>(
  object: mcs_proto.IDataMessageStanza,
  keys: Types.Keys,
): T {
  if (!object.appData) throw new Error("appData is missing");

  const cryptoKey = object.appData.find((item) => item.key === "crypto-key");
  if (!cryptoKey) {
    debug(object);
    debug(JSON.stringify(object));
    throw new Error("crypto-key is missing");
  }

  const salt = object.appData.find((item) => item.key === "encryption");
  if (!salt) throw new Error("salt is missing");

  const dh = crypto.createECDH("prime256v1");
  dh.setPrivateKey(keys.privateKey, "base64");

  const params = {
    version: "aesgcm",
    authSecret: keys.authSecret,
    dh: cryptoKey.value.slice(3),
    privateKey: dh,
    salt: salt.value.slice(5),
  };
  const decrypted = ece.decrypt(object.rawData, params);

  return JSON.parse(decrypted);
}
