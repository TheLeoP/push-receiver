import crypto from "crypto";
// @ts-ignore: this library does not include types
import * as ece from "http_ece";

import type * as Types from "../types.js";
import { mcs_proto } from "../protos.js";

function parseHeaderParams(header: string) {
  return Object.fromEntries(
    header.split(";").map((part) => {
      const [key, ...rest] = part.trim().split("=");
      const trimmedKey = key.trim();
      const value = rest.join("=").trim();
      return [trimmedKey, value];
    }),
  );
}

// https://tools.ietf.org/html/draft-ietf-webpush-encryption-03
export default function decrypt<T>(
  object: mcs_proto.IDataMessageStanza,
  keys: Types.Keys,
): T {
  if (!object.appData) throw new Error("appData is missing");

  const cryptoKey = object.appData.find((item) => item.key === "crypto-key");
  if (!cryptoKey) throw new Error("crypto-key is missing");

  const salt = object.appData.find((item) => item.key === "encryption");
  if (!salt) throw new Error("salt is missing");

  const cryptoKeyParams = parseHeaderParams(cryptoKey.value);
  const saltParams = parseHeaderParams(salt.value);
  if (!cryptoKeyParams.dh)
    throw new Error("crypto-key header is missing dh parameter");
  if (!saltParams.salt)
    throw new Error("encryption header is missing salt parameter");

  const dh = crypto.createECDH("prime256v1");
  dh.setPrivateKey(keys.privateKey, "base64");

  const params = {
    version: "aesgcm",
    authSecret: keys.authSecret,
    dh: cryptoKeyParams.dh,
    privateKey: dh,
    salt: saltParams.salt,
  };
  const decrypted = ece.decrypt(object.rawData, params);
  const out = JSON.parse(decrypted);
  if (!out) throw new Error("couldn't parse decrypted object");

  return out;
}
