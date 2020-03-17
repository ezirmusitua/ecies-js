import { Key } from "js-crypto-key-utils";
import * as ECKey from "eckey";
import * as conv from "binstring";
import * as x509 from '@fidm/x509';

export function readPublicKeyFromCertPem(pemContent) {
  const cert = x509.Certificate.fromPEM(pemContent);
  return cert.publicKey.keyRaw;
}

export async function readPrivateKeyFromKeyPem(pemContent) {
  const keyObj = new Key("pem", pemContent, { namedCurve: "P-256" });
  const prvKeyInHex = await keyObj.oct;
  return new ECKey(
    conv(prvKeyInHex, { in: "hex", out: "buffer" }),
    false
  ).key;
}
