const { Key } = require("js-crypto-key-utils");
const ECKey = require("eckey");
const conv = require("binstring");
const x509 = require("@fidm/x509");

const EC_ALGOS = {
  secp256r1: "P-256",
  prime256v1: "P-256",
  "P-256": "P-256",
  secp256k1: "P-256K",
  "P-256K": "P-256K",
  "P-384": "P-384",
  secp384r1: "P-384",
  "P-521": "P-521",
  secp521r1: "P-521"
};

function readPublicKeyFromCertPem(pemContent) {
  const cert = x509.Certificate.fromPEM(pemContent);
  return cert.publicKey.keyRaw;
}

async function readPrivateKeyFromKeyPem(pemContent, ecAlgo = "prime256v1") {
  const keyObj = new Key("pem", pemContent, { namedCurve: EC_ALGOS[ecAlgo] });
  const prvKeyInHex = await keyObj.oct;
  return new ECKey(conv(prvKeyInHex, { in: "hex", out: "buffer" }), false).key;
}

module.exports = {
  readPrivateKeyFromKeyPem,
  readPublicKeyFromCertPem
};
